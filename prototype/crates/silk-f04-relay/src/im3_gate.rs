//! Disabled IM3 original-stream preparation and complete native cycle owners.
//! No default routing or operational admission. Only a genuine complete middle
//! gate can disclose B frames; producer opening requires its full signed chain.
use crate::{
    Digest, Error, Result,
    aip2_claim::{
        ClaimPinRetention, ClaimRole, ConsumedScope, PreparedClaimBinding, PreparedScopeStore,
    },
    aip2_profile::PreparedProfile,
    aip2_proof::{PreparedProofVerifier, canonical_scalar, semaphore_scalar},
    aip2_transport::PreparedR2Context,
    config::SignedConfig,
    frame::{FRAME_BYTES, HpkePrivate, random, shuffle},
    manifest::SignedManifest,
    message,
};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use silk_sapling_f04::codec::domain_hash;
use std::{collections::BTreeSet, time::Instant};
use zeroize::Zeroizing;

/// Independently selected C pins. Different key bytes do not prove custody.
pub struct MiddlePins {
    /// Ed25519 identity.
    pub signing: Digest,
    /// HPKE key.
    pub hpke: Digest,
    /// TLS identity.
    pub tls: Digest,
}
/// Canonical 512-byte IM3-60-v1 overlay, signed A/C/B.
pub struct PreparedQ {
    bytes: [u8; 512],
    id: Digest,
}
impl PreparedQ {
    /// Exact C listener policy from the signed overlay. No role/custody admission.
    pub fn endpoint(&self) -> crate::config::Endpoint {
        crate::config::Endpoint {
            address: self.bytes[224..240].try_into().expect("16"),
            port: u16::from_le_bytes(self.bytes[240..242].try_into().expect("2")),
            signing: self.bytes[128..160].try_into().expect("32"),
            spki: self.bytes[192..224].try_into().expect("32"),
        }
    }
    /// Verify immutable local configuration/profile/pins and all signatures.
    pub fn verify(
        input: &[u8],
        config: &SignedConfig,
        profile: &PreparedProfile,
        pins: &MiddlePins,
    ) -> Result<Self> {
        let bytes: [u8; 512] = input
            .try_into()
            .map_err(|_| Error::Invalid("IM3 Q length"))?;
        let first = u64::from(config.epoch()) * 2880;
        let endpoints = config.endpoints();
        if &bytes[..8] != b"SNIM3P01"
            || bytes[8..40] != config.domain()
            || bytes[40..72] != config.id()
            || bytes[72..104] != profile.id()
            || bytes[104..108] != config.epoch().to_le_bytes()
            || bytes[108..112] != config.cohort().to_le_bytes()
            || bytes[112..120] != first.to_le_bytes()
            || bytes[120..128] != (first + 2880).to_le_bytes()
            || bytes[128..160] != pins.signing
            || bytes[160..192] != pins.hpke
            || bytes[192..224] != pins.tls
            || bytes[224..240] == [0; 16]
            || bytes[240..242] == [0; 2]
            || bytes[242..244] != [0; 2]
            || bytes[244..276] != domain_hash("SilkNode-IM3-policy", &[b"IM3-60-v1"])
            || bytes[276..320] != [0; 44]
            || [pins.signing, pins.hpke, pins.tls].contains(&[0; 32])
            || endpoints
                .iter()
                .any(|e| e.signing == pins.signing || e.spki == pins.tls)
            || config.hpke_keys().contains(&pins.hpke)
        {
            return Err(Error::Invalid("IM3 Q context/pins"));
        }
        let signed = message("SilkNode-IM3-profile-sign", &[&bytes[..320]]);
        for (key, at) in [
            (endpoints[0].signing, 320),
            (pins.signing, 384),
            (endpoints[1].signing, 448),
        ] {
            if !crate::aip2_signature(&key, &signed, &bytes[at..at + 64]) {
                return Err(Error::Invalid("IM3 Q signature"));
            }
        }
        Ok(Self {
            id: domain_hash("SilkNode-IM3-profile", &[&bytes[..320]]),
            bytes,
        })
    }
    /// Signed immutable overlay identifier.
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Exact overlay bytes; no activation capability.
    pub const fn bytes(&self) -> &[u8; 512] {
        &self.bytes
    }
}

/// One immutable even-round context; never inferred from a peer frame.
pub struct MiddleContext<'a> {
    r2: PreparedR2Context<'a>,
    profile: &'a PreparedProfile,
    q: &'a PreparedQ,
}
impl<'a> MiddleContext<'a> {
    /// Recheck exact Cfg/P/VK/M/Q linkage before any input ownership.
    pub fn new(
        config: &'a SignedConfig,
        manifest: &'a SignedManifest,
        profile: &'a PreparedProfile,
        vk_hash: Digest,
        q: &'a PreparedQ,
    ) -> Result<Self> {
        let r2 = PreparedR2Context::new(config, manifest, profile, vk_hash)?;
        if manifest.round() % 2 != 0
            || q.bytes[40..72] != config.id()
            || q.bytes[72..104] != profile.id()
        {
            return Err(Error::Invalid("IM3 even round/Q context"));
        }
        Ok(Self { r2, profile, q })
    }
    fn header(&self, stage: u8) -> Result<[u8; 64]> {
        let mut h = self.r2.round.header(stage, 0)?;
        h[..8].copy_from_slice(b"SNIM3D01");
        h[8..10].copy_from_slice(&1u16.to_le_bytes());
        Ok(h)
    }
    fn info(&self, h: &[u8], key: &Digest) -> Vec<u8> {
        message(
            "SilkNode-IM3-HPKE",
            &[
                &self.r2.round.config.id(),
                &self.profile.id(),
                &self.q.id(),
                &self.r2.round.manifest.id(),
                h,
                key,
            ],
        )
    }
    fn c_key(&self) -> Digest {
        self.q.bytes[160..192].try_into().expect("32")
    }
    fn scope(&self) -> Digest {
        let c = self.r2.round.config;
        semaphore_scalar(&domain_hash(
            "SilkNode-IM3-middle-scope",
            &[
                &c.domain(),
                &c.id(),
                &self.profile.id(),
                &self.q.id(),
                &c.cohort().to_le_bytes(),
                &c.epoch().to_le_bytes(),
                &self.r2.round.manifest.round().to_le_bytes(),
            ],
        ))
    }
    fn prefix(&self) -> [u8; 128] {
        let c = self.r2.round.config;
        let mut p = [0; 128];
        p[..8].copy_from_slice(b"SNIM3Z01");
        p[16..24].copy_from_slice(&self.r2.round.manifest.round().to_le_bytes());
        p[24..56].copy_from_slice(&c.domain());
        p[56..60].copy_from_slice(&c.cohort().to_le_bytes());
        p[60..64].copy_from_slice(&c.epoch().to_le_bytes());
        p[64..96].copy_from_slice(&self.q.id());
        p[96..128].copy_from_slice(&self.r2.round.manifest.id());
        p
    }
    /// Local store binding; changing Q never reopens the same P/round.
    pub fn claim_binding(&self) -> PreparedClaimBinding {
        self.profile.claim_binding(ClaimRole::Middle)
    }
    fn choice(&self) -> Digest {
        domain_hash(
            "SilkNode-IM3-middle-claim",
            &[&self.prefix(), &self.profile.id()],
        )
    }
    fn batch_hash(&self, role: &'static str, frames: &[MiddleFrame]) -> Digest {
        let c = self.r2.round.config;
        let r = self.r2.round.manifest.round().to_le_bytes();
        let cid = c.id();
        let pid = self.profile.id();
        let qid = self.q.id();
        let mid = self.r2.round.manifest.id();
        let mut parts: Vec<&[u8]> = vec![&cid, &pid, &qid, &mid, &r];
        parts.extend(frames.iter().map(|f| f.bytes().as_slice()));
        domain_hash(role, &parts)
    }
}

/// Exact version-separated IM3 frame; not a legacy frame or release input.
pub struct MiddleFrame(Box<[u8; FRAME_BYTES]>);
impl MiddleFrame {
    /// Strict header, length and zero padding. Authentication is checked inside owners.
    pub fn decode(bytes: &[u8], c: &MiddleContext<'_>, stage: u8) -> Result<Self> {
        let end = match stage {
            1 => 5232,
            2 => 4720,
            3 => 4208,
            _ => return Err(Error::Invalid("IM3 stage")),
        };
        if bytes.len() != FRAME_BYTES
            || bytes[..64] != c.header(stage)?
            || bytes[end..].iter().any(|x| *x != 0)
        {
            return Err(Error::Invalid("IM3 frame"));
        }
        let mut b = Box::new([0; FRAME_BYTES]);
        b.copy_from_slice(bytes);
        Ok(Self(b))
    }
    /// Exact public ciphertext frame bytes. C's B outputs are not constructed until disclosure.
    pub fn bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }
    fn tag(&self) -> Digest {
        self.0[64..96].try_into().expect("32")
    }
}
fn seal(c: &MiddleContext<'_>, stage: u8, recipient: Digest, plain: &[u8]) -> Result<Vec<u8>> {
    let h = c.header(stage)?;
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient)
        .map_err(|_| Error::Invalid("IM3 recipient"))?;
    let (enc, ct) = single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        &c.info(&h, &recipient),
        plain,
        &h,
        &mut random()?,
    )
    .map_err(|_| Error::Unavailable("IM3 seal"))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}
fn open(
    c: &MiddleContext<'_>,
    stage: u8,
    recipient: Digest,
    key: &HpkePrivate,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if X25519HkdfSha256::sk_to_pk(key).to_bytes().as_slice() != recipient {
        return Err(Error::Unavailable("IM3 local key"));
    }
    let h = c.header(stage)?;
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&ciphertext[..32])
        .map_err(|_| Error::Invalid("IM3 encapsulation"))?;
    let out = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        key,
        &enc,
        &c.info(&h, &recipient),
        &ciphertext[32..],
        &h,
    )
    .map_err(|_| Error::Invalid("IM3 authentication"))?;
    Ok(Zeroizing::new(out))
}
fn frame(c: &MiddleContext<'_>, stage: u8, cipher: &[u8]) -> Result<MiddleFrame> {
    let mut b = [0; FRAME_BYTES];
    b[..64].copy_from_slice(&c.header(stage)?);
    b[64..64 + cipher.len()].copy_from_slice(cipher);
    MiddleFrame::decode(&b, c, stage)
}
fn middle_message(plain: &[u8; 4608]) -> Digest {
    semaphore_scalar(&domain_hash(
        "SilkNode-IM3-middle-message",
        &[&plain[..128], &plain[416..]],
    ))
}

/// Client retains the exact B ciphertext internally while its middle proof runs.
/// No export of B bytes, nullifier or path is provided.
pub struct PendingMiddle<'c, 'a, 's, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    _claim: ConsumedScope<'s, P>,
    plain: Box<Zeroizing<[u8; 4608]>>,
}
impl<'c, 'a, 's, P: ClaimPinRetention> PendingMiddle<'c, 'a, 's, P> {
    /// Begin only after one client choice was durably consumed and its genuine B
    /// proof is available. The full two-job client lifecycle is a subsequent slice.
    pub fn from_b_cell(
        c: &'c MiddleContext<'a>,
        claim: ConsumedScope<'s, P>,
        cell: &[u8; 4096],
        verifier: &PreparedProofVerifier,
    ) -> Result<Self> {
        let msg = c.r2.check_cell(cell)?;
        Self::from_bound_b_cell(c, claim, cell, verifier, msg)
    }
    // Only the one-shot client owner may bind the durable claim to Q/M/Bmsg
    // instead of the legacy Bmsg. Never expose a caller-selected claim digest.
    fn from_bound_b_cell(
        c: &'c MiddleContext<'a>,
        claim: ConsumedScope<'s, P>,
        cell: &[u8; 4096],
        verifier: &PreparedProofVerifier,
        choice: Digest,
    ) -> Result<Self> {
        let msg = c.r2.check_cell(cell)?;
        if claim.binding() != c.profile.claim_binding(ClaimRole::Client)
            || claim.round() != c.r2.round.manifest.round()
            || claim.manifest() != c.r2.round.manifest.id()
            || claim.message() != choice
            || verifier.key_hash() != claim.binding().vk_hash
        {
            return Err(Error::Invalid("IM3 client claim"));
        }
        let s =
            crate::aip2_proof::prepare_cover_statement(c.profile, claim.manifest(), claim.round())
                .map_err(|_| Error::Invalid("IM3 B statement"))?;
        verifier
            .verify(
                cell[160..416].try_into().expect("256"),
                &[
                    s.root(),
                    cell[128..160].try_into().expect("32"),
                    msg,
                    s.scope(),
                ],
            )
            .map_err(|_| Error::Invalid("IM3 client B proof"))?;
        let inner = seal(c, 3, c.r2.round.config.hpke_keys()[1], cell)?;
        let mut plain = Box::new(Zeroizing::new([0; 4608]));
        plain[..128].copy_from_slice(&c.prefix());
        plain[416..4560].copy_from_slice(&inner);
        Ok(Self {
            c,
            _claim: claim,
            plain,
        })
    }
    /// Public root/message/scope only, for the one local proof job. No S_B export.
    pub fn statement(&self) -> [Digest; 3] {
        [
            self.c.profile.root(),
            middle_message(&self.plain),
            self.c.scope(),
        ]
    }
    /// Consume this owner once; verify the genuine C proof, then seal C and A.
    pub fn finish(
        mut self,
        nullifier: Digest,
        proof: &[u8; 256],
        verifier: &PreparedProofVerifier,
    ) -> Result<MiddleFrame> {
        if verifier.key_hash() != self.c.claim_binding().vk_hash {
            return Err(Error::Invalid("IM3 client C verifier"));
        }
        canonical_scalar(&nullifier).map_err(|_| Error::Invalid("IM3 client C scalar"))?;
        let [root, msg, scope] = self.statement();
        verifier
            .verify(proof, &[root, nullifier, msg, scope])
            .map_err(|_| Error::Invalid("IM3 client C proof"))?;
        self.plain[128..160].copy_from_slice(&nullifier);
        self.plain[160..416].copy_from_slice(proof);
        seal_onion(self.c, self.plain.as_ref())
    }
}
fn seal_onion(c: &MiddleContext<'_>, plain: &[u8; 4608]) -> Result<MiddleFrame> {
    let middle = seal(c, 2, c.c_key(), plain)?;
    let mut outer = Zeroizing::new([0; 5120]);
    outer[..64].copy_from_slice(&c.header(2)?);
    outer[64..4720].copy_from_slice(&middle);
    let sealed = seal(c, 1, c.r2.round.config.hpke_keys()[0], outer.as_ref())?;
    frame(c, 1, &sealed)
}
/// A opens only its layer. No middle decryption or B extraction API exists.
pub fn open_at_a(c: &MiddleContext<'_>, key: &HpkePrivate, f: &MiddleFrame) -> Result<MiddleFrame> {
    MiddleFrame::decode(f.bytes(), c, 1)?;
    let p = open(
        c,
        1,
        c.r2.round.config.hpke_keys()[0],
        key,
        &f.bytes()[64..5232],
    )?;
    if p.len() != 5120 || p[..64] != c.header(2)? || p[4720..].iter().any(|x| *x != 0) {
        return Err(Error::Invalid("IM3 A plaintext"));
    }
    frame(c, 2, &p[64..4720])
}
/// A's private permutation cannot construct C output or bypass C's gate.
pub fn permute_at_a(c: &MiddleContext<'_>, frames: &mut [MiddleFrame; 32]) -> Result<()> {
    let mut tags = BTreeSet::new();
    for f in frames.iter() {
        MiddleFrame::decode(f.bytes(), c, 2)?;
        if !tags.insert(f.tag()) {
            return Err(Error::Invalid("IM3 A duplicate"));
        }
    }
    shuffle(frames)
}

/// Signed A_READY input commitment. Authenticating A does not accept its inputs.
pub struct PreparedAReady {
    hash: Digest,
    control: Im3Control,
}
impl PreparedAReady {
    /// Check exact canonical A_READY control, local round/N/Q/M and A signature.
    pub fn verify(bytes: &[u8], c: &MiddleContext<'_>) -> Result<Self> {
        let control = Im3Control::verify(bytes, c)?;
        if control.kind() != Im3Kind::AReady {
            return Err(Error::Invalid("IM3 A_READY"));
        }
        Ok(Self {
            hash: control.field(116),
            control,
        })
    }
}
/// Claimed once before inputs. Owns all frames; no per-frame decryption/output.
pub struct MiddleBatchOwner<'c, 'a, 's, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    claim: ConsumedScope<'s, P>,
    frames: Vec<MiddleFrame>,
    tags: BTreeSet<Digest>,
    failed: bool,
}
impl<'c, 'a, 's, P: ClaimPinRetention> MiddleBatchOwner<'c, 'a, 's, P> {
    /// Durably claim P/round and bind Q/M before any frame enters the owner.
    pub fn begin(c: &'c MiddleContext<'a>, store: &'s mut PreparedScopeStore<P>) -> Result<Self> {
        if store.binding() != c.claim_binding() {
            return Err(Error::Invalid("IM3 middle store binding"));
        }
        let claim = store
            .consume(
                c.r2.round.manifest.round(),
                c.r2.round.manifest.id(),
                c.choice(),
            )
            .map_err(|_| Error::Unavailable("IM3 middle claim"))?;
        Ok(Self {
            c,
            claim,
            frames: Vec::with_capacity(32),
            tags: BTreeSet::new(),
            failed: false,
        })
    }
    /// Admit exactly one canonical stage-2 frame. Any invalid, extra or duplicate
    /// input permanently closes this live attempt; there is no replacement API.
    pub fn admit(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(Error::Unavailable("IM3 input owner closed"));
        }
        self.failed = true;
        if self.frames.len() == 32 {
            return Err(Error::Invalid("IM3 extra input"));
        }
        let f = MiddleFrame::decode(bytes, self.c, 2)?;
        if !self.tags.insert(f.tag()) {
            return Err(Error::Invalid("IM3 duplicate C encapsulation"));
        }
        self.frames.push(f);
        self.failed = false;
        Ok(())
    }
    /// Freeze complete exact input, check A_READY, decrypt internally, verify all
    /// genuine C proofs and distinct nullifiers/B tags, strip metadata, shuffle
    /// once, and persist DisclosureDecided before returning any B capability.
    /// This disabled preparation takes a caller-owned deadline; runtime schedule
    /// and original-connection writes require the separate IM3 owner integration.
    #[cfg(test)]
    fn disclose(
        self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
        ready: PreparedAReady,
        deadline: Instant,
    ) -> Result<DisclosureDecided> {
        self.verify_complete(key, verifier, ready, deadline)?
            .decide(deadline)
    }
    fn verify_complete(
        mut self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
        ready: PreparedAReady,
        deadline: Instant,
    ) -> Result<VerifiedMiddleOutput<'s, P>> {
        before(deadline)?;
        if self.failed
            || self.frames.len() != 32
            || verifier.key_hash() != self.c.claim_binding().vk_hash
            || self.c.batch_hash("SilkNode-IM3-A-batch", &self.frames) != ready.hash
        {
            return Err(Error::Invalid("IM3 complete input/verifier/readiness"));
        }
        let mut nullifiers = BTreeSet::new();
        let mut inner_tags = BTreeSet::new();
        let mut inner: Vec<Box<Zeroizing<[u8; 4144]>>> = Vec::with_capacity(32);
        for f in &self.frames {
            before(deadline)?;
            let p = open(self.c, 2, self.c.c_key(), key, &f.bytes()[64..4720])?;
            let p: &[u8; 4608] = p
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("IM3 C plaintext size"))?;
            if p[..128] != self.c.prefix() || p[4560..] != [0; 48] {
                return Err(Error::Invalid("IM3 C plaintext context"));
            }
            let n: Digest = p[128..160].try_into().expect("32");
            canonical_scalar(&n).map_err(|_| Error::Invalid("IM3 C nullifier"))?;
            if !nullifiers.insert(n)
                || !inner_tags.insert(<Digest>::try_from(&p[416..448]).expect("32"))
            {
                return Err(Error::Invalid("IM3 duplicate nullifier/B encapsulation"));
            }
            verifier
                .verify(
                    p[160..416].try_into().expect("256"),
                    &[self.c.profile.root(), n, middle_message(p), self.c.scope()],
                )
                .map_err(|_| Error::Invalid("IM3 C membership"))?;
            before(deadline)?;
            let mut b = Box::new(Zeroizing::new([0; 4144]));
            b.copy_from_slice(&p[416..4560]);
            inner.push(b);
        }
        // Destroy source-bearing frames/proof/nullifier material before output.
        self.frames.clear();
        self.tags.clear();
        drop(nullifiers);
        drop(inner_tags);
        let mut inner: [Box<Zeroizing<[u8; 4144]>>; 32] = inner
            .try_into()
            .map_err(|_| Error::Unavailable("IM3 complete verified count"))?;
        shuffle(&mut inner)?;
        before(deadline)?;
        let mut outputs = Vec::with_capacity(32);
        for b in inner {
            outputs.push(frame(self.c, 3, b.as_ref().as_ref())?);
        }
        let hash = self.c.batch_hash("SilkNode-IM3-C-batch", &outputs);
        before(deadline)?;
        Ok(VerifiedMiddleOutput {
            claim: self.claim,
            a_ready: ready.control,
            frames: outputs
                .try_into()
                .map_err(|_| Error::Unavailable("IM3 output count"))?,
            hash,
        })
    }
}
struct VerifiedMiddleOutput<'s, P: ClaimPinRetention> {
    claim: ConsumedScope<'s, P>,
    a_ready: Im3Control,
    frames: [MiddleFrame; 32],
    hash: Digest,
}
impl<P: ClaimPinRetention> VerifiedMiddleOutput<'_, P> {
    fn decide(mut self, deadline: Instant) -> Result<DisclosureDecided> {
        before(deadline)?;
        self.claim
            .decide_disclosure(self.hash)
            .map_err(|_| Error::Unavailable("IM3 disclosure fence"))?;
        // A late return never rewinds a durable decision or grants another try.
        before(deadline)?;
        Ok(DisclosureDecided {
            frames: self.frames,
            hash: self.hash,
            a_ready: self.a_ready,
        })
    }
}
fn before(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Unavailable("IM3 original deadline"))
    } else {
        Ok(())
    }
}
/// Only the complete genuine gate and durable decision construct this type.
/// No Clone/Deserialize/reopen/legacy conversion. Dropping never permits retry.
pub struct DisclosureDecided {
    frames: [MiddleFrame; 32],
    hash: Digest,
    a_ready: Im3Control,
}
impl DisclosureDecided {
    /// Aggregate commitment only; no pairing/source index or middle proof label.
    pub const fn output_hash(&self) -> Digest {
        self.hash
    }
    /// Consume the original preparation capability once. Runtime must bind these
    /// writes to its original connection/deadline; no restart export is possible.
    #[cfg(test)]
    fn into_frames(self) -> [MiddleFrame; 32] {
        self.frames
    }
}

use crate::{
    im3_schedule::{Im3Guard, Im3Schedule, Phase},
    tls::{RecordSize, Transport},
};
/// Timed C preparation bound to the original native lease and B connection.
/// No caller-selected disclosure deadline or replacement output link exists.
pub(crate) struct TimedMiddleOwner<'c, 'a, 's, 't, P: ClaimPinRetention> {
    owner: MiddleBatchOwner<'c, 'a, 's, P>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    output: &'t mut Transport,
    ready: Option<PreparedAReady>,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> TimedMiddleOwner<'c, 'a, 's, 't, P> {
    /// Claim one pinned Q/M before T-5, with a lease armed before T-10 and
    /// the already established exact B endpoint. This starts no socket service.
    pub fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        output: &'t mut Transport,
    ) -> Result<Self> {
        let preflight = (|| {
            guard.check(schedule)?;
            if schedule.round() != c.r2.round.manifest.round() {
                return Err(Error::Invalid("IM3 scheduled context"));
            }
            before(schedule.at(-5_000_000_000)?)?;
            output.check_endpoint(c.r2.round.config.endpoints()[1], true)
        })();
        if let Err(e) = preflight {
            let _ = output.quarantine();
            return Err(e);
        }
        let owner = match MiddleBatchOwner::begin(c, store) {
            Ok(v) => v,
            Err(e) => {
                let _ = output.quarantine();
                return Err(e);
            }
        };
        if let Err(e) = before(schedule.at(-5_000_000_000)?).and_then(|()| guard.check(schedule)) {
            let _ = output.quarantine();
            return Err(e);
        }
        Ok(Self {
            owner,
            schedule,
            guard,
            output,
            ready: None,
        })
    }
    /// Original C receive envelope [T+14.5,T+17.5). No sender arrival timestamp
    /// can backdate an input and no successful input produces a B frame.
    pub fn admit(&mut self, bytes: &[u8]) -> Result<()> {
        let result = (|| {
            let ordinal = u8::try_from(self.owner.frames.len())
                .map_err(|_| Error::Invalid("IM3 C input ordinal"))?;
            let early = 14_500_000_000 + 7_812_500 * i64::from(ordinal);
            self.receive_window(early)?;
            self.owner.admit(bytes)?;
            self.receive_window(early)
        })();
        if result.is_err() {
            self.owner.failed = true;
        }
        result
    }
    /// Validate exactly one original A_READY after the complete data stream,
    /// within its receive envelope [T+14.75,T+17.5). No gate-phase replacement
    /// or caller-supplied prevalidated readiness can complete this owner.
    pub fn admit_ready(&mut self, bytes: &[u8]) -> Result<()> {
        let result = (|| {
            self.receive_window(14_750_000_000)?;
            if self.owner.failed || self.owner.frames.len() != 32 || self.ready.is_some() {
                return Err(Error::Invalid("IM3 readiness stream/duplicate"));
            }
            let ready = PreparedAReady::verify(bytes, self.owner.c)?;
            self.receive_window(14_750_000_000)?;
            self.ready = Some(ready);
            Ok(())
        })();
        if result.is_err() {
            self.owner.failed = true;
        }
        result
    }
    fn receive_window(&self, early: i64) -> Result<()> {
        self.guard.check(self.schedule)?;
        let now = Instant::now();
        if now < self.schedule.at(early)? || now >= self.schedule.at(17_500_000_000)? {
            return Err(Error::Unavailable("IM3 C receive window"));
        }
        Ok(())
    }
    /// Freeze and genuinely verify only in the fixed C gate phase. The complete
    /// result still has no ciphertext getter or socket write capability.
    pub fn verify(
        self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
    ) -> Result<TimedMiddleVerified<'s, 't, P>> {
        // One failure exit includes initial phase/guard checks: an outer
        // preflight cannot eliminate preemption between these checks.
        let verified = (|| {
            self.schedule.require(self.guard, Phase::CGate)?;
            let ready = self
                .ready
                .ok_or(Error::Invalid("IM3 readiness absent at freeze"))?;
            let verified = self.owner.verify_complete(
                key,
                verifier,
                ready,
                self.schedule.window(Phase::CGate)?.1,
            )?;
            self.schedule.require(self.guard, Phase::CGate)?;
            Ok(verified)
        })();
        let verified = match verified {
            Ok(v) => v,
            Err(error) => {
                let _ = self.output.quarantine();
                return Err(error);
            }
        };
        Ok(TimedMiddleVerified {
            verified,
            schedule: self.schedule,
            guard: self.guard,
            output: self.output,
        })
    }
}
/// Complete verified batch awaiting its original persistence phase. No B export.
pub struct TimedMiddleVerified<'s, 't, P: ClaimPinRetention> {
    verified: VerifiedMiddleOutput<'s, P>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    output: &'t mut Transport,
}
impl<'t, P: ClaimPinRetention> TimedMiddleVerified<'_, 't, P> {
    /// Persist DisclosureDecided during [T+19.25,T+19.5), before the first write.
    pub fn decide(self) -> Result<TimedMiddleDisclosure<'t>> {
        self.schedule.require(self.guard, Phase::CDecision)?;
        let decided = self
            .verified
            .decide(self.schedule.window(Phase::CDecision)?.1)?;
        Ok(TimedMiddleDisclosure {
            decided,
            schedule: self.schedule,
            guard: self.guard,
            output: self.output,
            index: 0,
            queued: false,
            failed: false,
            observation: None,
            ready_controls: None,
            ready_index: 0,
            cleaned_up: false,
        })
    }
}
/// Original fixed-slot writes only. This owns the connection borrow and exposes
/// neither B records nor a replacement-connection/replay method.
pub struct TimedMiddleDisclosure<'t> {
    decided: DisclosureDecided,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    output: &'t mut Transport,
    index: u8,
    queued: bool,
    failed: bool,
    observation: Option<crate::tls::WireObservation>,
    ready_controls: Option<[Im3Control; 2]>,
    ready_index: u8,
    cleaned_up: bool,
}
impl TimedMiddleDisclosure<'_> {
    /// Aggregate output commitment for the subsequent C_READY chain.
    pub const fn output_hash(&self) -> Digest {
        self.decided.hash
    }
    /// Take the last actual socket-step observation, including a failed step.
    /// Empty before any socket attempt; no input/output mapping is included.
    pub fn take_wire_observation(&mut self) -> Option<crate::tls::WireObservation> {
        self.observation.take()
    }
    /// Advance at most one socket write on the original record and slot.
    /// Success means local completion only. Any error is irreversible exposure
    /// uncertainty and permanently closes this owner and connection.
    pub fn poll(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 disclosure failed"));
        }
        if self.index == 32 {
            return Ok(true);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
            let _ = self.output.quarantine();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        self.guard.check(self.schedule)?;
        let (start, end) = self.schedule.relay_slot(true, self.index)?;
        let now = Instant::now();
        if now < start {
            return Ok(false);
        }
        before(end)?;
        if !self.queued {
            self.output.queue(
                RecordSize::Cell,
                self.decided.frames[usize::from(self.index)].bytes(),
                end,
            )?;
            self.queued = true;
        }
        let (result, observation) = self.output.write_step_observed();
        self.observation = Some(observation);
        if result? {
            self.index += 1;
            self.queued = false;
        }
        Ok(self.index == 32)
    }
    /// After the exact32 original writes, forward the complete original signed
    /// A_READY then C_READY in [20.25,20.5), on that same B connection only.
    /// C_READY is constructed only from this genuinely verified, durably
    /// decided batch; no caller-supplied hashes/control can authorize it.
    pub fn poll_ready(
        &mut self,
        c: &MiddleContext<'_>,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<bool> {
        let result = self.poll_ready_inner(c, key);
        if result.is_err() {
            self.failed = true;
            let _ = self.output.quarantine();
        }
        result
    }
    fn poll_ready_inner(
        &mut self,
        c: &MiddleContext<'_>,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<bool> {
        if self.failed || self.index != 32 {
            return Err(Error::Unavailable(
                "IM3 readiness before completed disclosure",
            ));
        }
        self.guard.check(self.schedule)?;
        if self.ready_index == 2 {
            return Ok(true);
        }
        let (start, end) = self.schedule.window(Phase::CReady)?;
        if Instant::now() < start {
            return Ok(false);
        }
        self.schedule.require(self.guard, Phase::CReady)?;
        if self.ready_controls.is_none() {
            let a = Im3Control::verify(self.decided.a_ready.bytes(), c)?;
            if a.kind() != Im3Kind::AReady
                || c.batch_hash("SilkNode-IM3-C-batch", &self.decided.frames) != self.decided.hash
            {
                return Err(Error::Invalid("IM3 decided readiness context"));
            }
            let middle = control::sign(
                c,
                Im3Kind::CReady,
                Im3Role::C,
                [
                    a.field(116),
                    self.decided.hash,
                    [0; 32],
                    a.id(),
                    [0; 32],
                    [0; 32],
                    [0; 32],
                ],
                key,
            )?;
            self.ready_controls = Some([a, middle]);
        }
        if !self.queued {
            self.output.queue(
                RecordSize::Control,
                self.ready_controls.as_ref().expect("initialized")[usize::from(self.ready_index)]
                    .bytes(),
                end,
            )?;
            self.queued = true;
        }
        let (result, observation) = self.output.write_step_observed();
        self.observation = Some(observation);
        if result? {
            self.schedule.require(self.guard, Phase::CReady)?;
            self.queued = false;
            self.ready_index += 1;
        }
        Ok(self.ready_index == 2)
    }
    /// Retain the same B output link through scheduled +44 cleanup. No replay
    /// or new disclosure is authorized by successful local write completion.
    pub fn poll_cleanup(&mut self) -> Result<bool> {
        let result = (|| {
            if self.failed || self.ready_index != 2 {
                return Err(Error::Unavailable("IM3 C cleanup before ready"));
            }
            if self.cleaned_up {
                return Ok(true);
            }
            self.guard.check(self.schedule)?;
            if Instant::now() < self.schedule.at(44_000_000_000)? {
                return Ok(false);
            }
            self.output.quarantine()?;
            self.cleaned_up = true;
            Ok(true)
        })();
        if result.is_err() {
            self.failed = true;
            let _ = self.output.quarantine();
        }
        result
    }
}

mod authorizer;
mod client;
mod control;
mod cycle;
mod exit;
mod exit_cycle;
mod ingress;
mod manifest_cycle;
mod producer;
mod receive;
mod runner;
mod sequence;
mod stage;
pub use authorizer::{AuthorizingIngressOwner, IngressControlReservation};
pub use client::{ClientProofJob, ClientProofOutput, PreparedClientOwner};
pub use control::{
    Im3AckChain, Im3Authorization, Im3Control, Im3Kind, Im3ReadyChain, Im3Release, Im3Role,
};
pub use exit_cycle::{CompletedExit, ExitControlReservation, ReleasingExitOwner};
#[cfg(test)]
mod tests;
pub use exit::{ReceivingExitOwner, VerifiedIm3Exit};
pub use ingress::{IngressTrain, ReceivingIngressOwner};
pub use manifest_cycle::{ManifestFanout, ManifestReceivingMiddle};
pub use producer::Im3ProducerOwner;
pub use receive::ReceivingMiddleOwner;
pub use runner::{
    Im3ClockSource, Im3RoleAdmission, Im3RoundPorts, Im3RoundRunner, Im3RoundTerminal,
};
pub use sequence::{Im3RoundAttempt, Im3RoundSequence};
pub use stage::{Im3StagedFrame, StagedIm3Exit};
