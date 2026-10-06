//! Default-off R2 encrypted preparation; executable lab requires a SECOND feature.
//! Mathematical fixture acceptance is not ceremony, clock or delivery approval.
use crate::{
    Digest, Error, Result,
    aip2_claim::{ClaimPinRetention, ClaimRole, ConsumedScope},
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::{
        PreparedProofVerifier, canonical_scalar, domain_hash, prepare_cover_statement,
        semaphore_scalar,
    },
    config::SignedConfig,
    control::{Kind, Role, SignedControl},
    frame::{FRAME_BYTES, HpkePrivate, Payload, RoundContext, random, shuffle},
    manifest::SignedManifest,
    message,
};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use silk_sapling_f04::{
    codec::EnvelopeView, crypto::verify_borrowed, parameters::SaplingVerificationKeys,
};
use std::{collections::BTreeSet, time::Instant};
use zeroize::Zeroizing;

/// Exact signed C/M/P linkage only. No local-cut, admission or timing authority.
pub struct PreparedR2Context<'a> {
    pub(crate) round: RoundContext<'a>,
    profile: &'a PreparedProfile,
}
impl<'a> PreparedR2Context<'a> {
    /// Recheck P against actual signature-checked configuration and role keys.
    /// `vk_hash` is a local byte pin, not a ceremony acceptance certificate.
    pub fn new(
        config: &'a SignedConfig,
        manifest: &'a SignedManifest,
        profile: &'a PreparedProfile,
        vk_hash: Digest,
    ) -> Result<Self> {
        let round = RoundContext::new(config, manifest)?;
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
        .map_err(|_| Error::Invalid("R2 exact configuration/profile linkage"))?;
        Ok(Self { round, profile })
    }
    fn header(&self, stage: u8) -> Result<[u8; 64]> {
        if !matches!(stage, 1 | 2) {
            return Err(Error::Invalid("R2 stage"));
        }
        let mut h = self.round.header(stage, 0)?;
        h[..8].copy_from_slice(b"SNMIX007");
        h[8..10].copy_from_slice(&7_u16.to_le_bytes());
        Ok(h)
    }
    fn info(&self, header: &[u8], recipient: &Digest) -> Vec<u8> {
        message(
            "SilkNode-AIP2R2-HPKE",
            &[
                &self.round.config.id(),
                &self.round.manifest.id(),
                &self.profile.id(),
                header,
                recipient,
            ],
        )
    }
    fn statement(&self) -> Result<crate::aip2_proof::PreparedCoverStatement> {
        prepare_cover_statement(
            self.profile,
            self.round.manifest.id(),
            self.round.manifest.round(),
        )
        .map_err(|_| Error::Invalid("R2 statement context"))
    }
    fn check_cell(&self, cell: &[u8; 4096]) -> Result<Digest> {
        let s = self.statement()?;
        if cell[..8] != s.cell()[..8]
            || cell[8] > 1
            || cell[9..128] != s.cell()[9..128]
            || cell[3206..].iter().any(|x| *x != 0)
            || (cell[8] == 0 && cell[416..3206].iter().any(|x| *x != 0))
        {
            return Err(Error::Invalid("R2 cell context/kind/padding"));
        }
        canonical_scalar(cell[128..160].try_into().expect("32"))
            .map_err(|_| Error::Invalid("R2 canonical nullifier"))?;
        Ok(semaphore_scalar(&domain_hash(
            "SilkNode-AIP2R2-message",
            &[&cell[..128], &cell[416..]],
        )))
    }
}

/// Version-separated stage1/2 bytes only; never a legacy Frame or producer input.
pub struct PreparedR2Frame(Box<[u8; FRAME_BYTES]>);
impl PreparedR2Frame {
    /// Exact stage1/2 length, version, context and zero-padding check only.
    /// Ciphertext authentication and membership checks are separate.
    pub fn decode(bytes: &[u8], c: &PreparedR2Context<'_>, stage: u8) -> Result<Self> {
        let end = match stage {
            1 => 4720,
            2 => 4208,
            _ => return Err(Error::Invalid("R2 stage")),
        };
        if bytes.len() != FRAME_BYTES
            || bytes[..64] != c.header(stage)?
            || bytes[end..].iter().any(|x| *x != 0)
        {
            return Err(Error::Invalid("R2 frame context/version/padding"));
        }
        let mut retained = Box::new([0; FRAME_BYTES]);
        retained.copy_from_slice(bytes);
        Ok(Self(retained))
    }
    /// Immutable ciphertext bytes; not submission, timing or release authority.
    pub fn bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }
    fn encapsulation(&self) -> Digest {
        self.0[64..96].try_into().expect("32")
    }
}
fn seal(
    c: &PreparedR2Context<'_>,
    h: &[u8; 64],
    recipient: &Digest,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| Error::Invalid("R2 HPKE public key"))?;
    let (enc, cipher) =
        single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &key,
            &c.info(h, recipient),
            plain,
            h,
            &mut random()?,
        )
        .map_err(|_| Error::Unavailable("R2 HPKE seal"))?;
    let mut output = enc.to_bytes().to_vec();
    output.extend_from_slice(&cipher);
    Ok(output)
}
fn open(
    c: &PreparedR2Context<'_>,
    h: &[u8],
    recipient: &Digest,
    key: &HpkePrivate,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if X25519HkdfSha256::sk_to_pk(key).to_bytes().as_slice() != recipient {
        return Err(Error::Unavailable("R2 wrong local HPKE key"));
    }
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&bytes[..32])
        .map_err(|_| Error::Invalid("R2 HPKE encapsulation"))?;
    let plain = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        key,
        &enc,
        &c.info(h, recipient),
        &bytes[32..],
        h,
    )
    .map_err(|_| Error::Invalid("R2 HPKE authentication"))?;
    Ok(Zeroizing::new(plain))
}
/// Consume the held client receipt before ciphertext can escape. Proof worker
/// dispatch must already have occurred under this SAME receipt's trusted owner.
/// This component does not dispatch a worker, persist ciphertext or submit it.
pub fn seal_claimed_cell<P: ClaimPinRetention>(
    c: &PreparedR2Context<'_>,
    claim: ConsumedScope<'_, P>,
    cell: &[u8; 4096],
) -> Result<PreparedR2Frame> {
    if claim.binding() != c.profile.claim_binding(ClaimRole::Client)
        || claim.round() != c.round.manifest.round()
        || claim.manifest() != c.round.manifest.id()
        || claim.message() != c.check_cell(cell)?
    {
        return Err(Error::Invalid("R2 client receipt/cell"));
    }
    let h2 = c.header(2)?;
    let inner = seal(c, &h2, &c.round.config.hpke_keys()[1], cell)?;
    if inner.len() != 4144 {
        return Err(Error::Unavailable("R2 inner size"));
    }
    let mut plain = Zeroizing::new([0; 4608]);
    plain[..64].copy_from_slice(&h2);
    plain[64..4208].copy_from_slice(&inner);
    let h1 = c.header(1)?;
    let outer = seal(c, &h1, &c.round.config.hpke_keys()[0], plain.as_ref())?;
    if outer.len() != 4656 {
        return Err(Error::Unavailable("R2 outer size"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..64].copy_from_slice(&h1);
    bytes[64..4720].copy_from_slice(&outer);
    PreparedR2Frame::decode(&bytes, c, 1)
}
/// A learns no kind, nullifier or proof. No source labels are retained.
pub fn open_a(
    c: &PreparedR2Context<'_>,
    key: &HpkePrivate,
    frame: &PreparedR2Frame,
) -> Result<PreparedR2Frame> {
    PreparedR2Frame::decode(frame.bytes(), c, 1)?;
    let plain = open(
        c,
        &frame.bytes()[..64],
        &c.round.config.hpke_keys()[0],
        key,
        &frame.bytes()[64..4720],
    )?;
    if plain.len() != 4608 || plain[..64] != c.header(2)? || plain[4208..].iter().any(|x| *x != 0) {
        return Err(Error::Invalid("R2 A plaintext"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..4208].copy_from_slice(&plain[..4208]);
    PreparedR2Frame::decode(&bytes, c, 2)
}
/// Only a full, duplicate-free actual stage2 array can be shuffled at A.
pub fn permute_at_a(c: &PreparedR2Context<'_>, frames: &mut [PreparedR2Frame; 32]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for f in frames.iter() {
        PreparedR2Frame::decode(f.bytes(), c, 2)?;
        if !seen.insert(f.encapsulation()) {
            return Err(Error::Invalid("R2 duplicate encapsulation"));
        }
    }
    shuffle(frames)
}
fn batch_id(c: &PreparedR2Context<'_>, frames: &[PreparedR2Frame; 32]) -> Result<Digest> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(34);
    let cfg = c.round.config.id();
    let m = c.round.manifest.id();
    parts.push(&cfg);
    parts.push(&m);
    for f in frames {
        PreparedR2Frame::decode(f.bytes(), c, 2)?;
        parts.push(f.bytes());
    }
    // Existing ordered batch hash, but over exact new R2 stage2 bytes.
    Ok(domain_hash("SilkNode-F0-A-batch", &parts))
}
/// Hash for A's original signed readiness; no membership/release authority.
pub fn prepared_a_batch_id(
    c: &PreparedR2Context<'_>,
    frames: &[PreparedR2Frame; 32],
) -> Result<Digest> {
    batch_id(c, frames)
}
/// Complete authenticated ciphertext owner, still no proof or payload authority.
pub struct CollectedR2Batch {
    frames: [PreparedR2Frame; 32],
    config: Digest,
    manifest: Digest,
    profile: Digest,
    round: u64,
    id: Digest,
}
impl CollectedR2Batch {
    /// Signature checking is supplied by SignedControl; completion/timing is a
    /// future runtime obligation. No caller-supplied count substitutes for 32.
    pub fn collect(
        c: &PreparedR2Context<'_>,
        frames: [PreparedR2Frame; 32],
        ready: &SignedControl,
    ) -> Result<Self> {
        let id = batch_id(c, &frames)?;
        let r = ready.bytes();
        if ready.kind() != Kind::AReady
            || ready.role() != Role::A
            || r[10] != 1
            || r[248] < 8
            || r[12..44] != c.round.config.domain()
            || r[44..76] != c.round.config.id()
            || r[76..80] != c.round.config.cohort().to_le_bytes()
            || r[80..88] != c.round.manifest.round().to_le_bytes()
            || r[88..120] != c.round.manifest.id()
            || r[120..152] != id
        {
            return Err(Error::Invalid("R2 complete original A_READY"));
        }
        let mut seen = BTreeSet::new();
        for f in &frames {
            if !seen.insert(f.encapsulation()) {
                return Err(Error::Invalid("R2 duplicate encapsulation"));
            }
        }
        Ok(Self {
            frames,
            config: c.round.config.id(),
            manifest: c.round.manifest.id(),
            profile: c.profile.id(),
            round: c.round.manifest.round(),
            id,
        })
    }
    /// Exit consistency digest: entire ordered ciphertext batch, not one
    /// client's message. No manifest/message change reopens (P,round).
    pub fn exit_consistency(&self) -> Digest {
        domain_hash(
            "SilkNode-AIP2R2-exit-batch",
            &[
                &self.config,
                &self.manifest,
                &self.profile,
                &self.round.to_le_bytes(),
                &self.id,
            ],
        )
    }
    /// Consume exit authority BEFORE decrypt/pairings; retain only envelope/kind
    /// after every proof passes. No Sapling work or partial output in this phase.
    pub fn verify_membership<P: ClaimPinRetention>(
        self,
        c: &PreparedR2Context<'_>,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
        claim: ConsumedScope<'_, P>,
        deadline: Instant,
    ) -> Result<CompleteR2Cohort> {
        complete_before(deadline)?;
        if self.config != c.round.config.id()
            || self.manifest != c.round.manifest.id()
            || self.profile != c.profile.id()
            || self.round != c.round.manifest.round()
            || claim.binding() != c.profile.claim_binding(ClaimRole::Exit)
            || claim.round() != self.round
            || claim.manifest() != self.manifest
            || claim.message() != self.exit_consistency()
            || verifier.key_hash() != claim.binding().vk_hash
        {
            return Err(Error::Invalid("R2 exit owner/verifier/batch"));
        }
        let statement = c.statement()?;
        let mut seen = BTreeSet::new();
        let mut stripped = Vec::with_capacity(32);
        for f in self.frames {
            complete_before(deadline)?;
            let plain = open(
                c,
                &f.bytes()[..64],
                &c.round.config.hpke_keys()[1],
                key,
                &f.bytes()[64..4208],
            )?;
            let cell: &[u8; 4096] = plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("R2 B plaintext length"))?;
            let msg = c.check_cell(cell)?;
            let nullifier: Digest = cell[128..160].try_into().expect("32");
            if !seen.insert(nullifier) {
                return Err(Error::Invalid("R2 duplicate round nullifier"));
            }
            verifier
                .verify(
                    cell[160..416].try_into().expect("256"),
                    &[statement.root(), nullifier, msg, statement.scope()],
                )
                .map_err(|_| Error::Invalid("R2 membership proof"))?;
            complete_before(deadline)?;
            // No envelope parsing or Sapling verification yet, even for early
            // valid records. Owned output has no proof/nullifier/source labels.
            let mut e = Box::new(Zeroizing::new([0; 2790]));
            e.copy_from_slice(&cell[416..3206]);
            stripped.push(Stripped {
                kind: cell[8],
                envelope: e,
            });
        }
        let mut stripped: [Stripped; 32] = stripped
            .try_into()
            .map_err(|_| Error::Unavailable("R2 complete count"))?;
        drop(seen);
        shuffle(&mut stripped)?;
        complete_before(deadline)?;
        Ok(CompleteR2Cohort {
            stripped,
            config: self.config,
            manifest: self.manifest,
            profile: self.profile,
            round: self.round,
        })
    }
}
struct Stripped {
    kind: u8,
    envelope: Box<Zeroizing<[u8; 2790]>>,
}
/// Only the genuine all32 verifier constructs this private pre-Sapling owner.
/// No public constructor, Clone, Deserialize or legacy conversion.
pub struct CompleteR2Cohort {
    stripped: [Stripped; 32],
    config: Digest,
    manifest: Digest,
    profile: Digest,
    round: u64,
}
impl CompleteR2Cohort {
    /// Fixed genuine-verified count, with no payload or member-label export.
    pub const fn count(&self) -> usize {
        32
    }
    /// Ordinary cut/framing/Sapling checks run AFTER the complete-proof gate
    /// and metadata removal/private permutation. None can produce partial output.
    /// Missing keys permits covers only; it never skips a real Sapling check.
    pub fn verify_sapling(
        self,
        c: &PreparedR2Context<'_>,
        keys: Option<&SaplingVerificationKeys>,
        deadline: Instant,
    ) -> Result<VerifiedR2Batch> {
        complete_before(deadline)?;
        if self.config != c.round.config.id()
            || self.manifest != c.round.manifest.id()
            || self.profile != c.profile.id()
            || self.round != c.round.manifest.round()
        {
            return Err(Error::Invalid("R2 complete payload context"));
        }
        let mut payloads = Vec::with_capacity(32);
        for s in self.stripped {
            complete_before(deadline)?;
            let p = if s.kind == 0 {
                Payload::cover()
            } else {
                let k = keys.ok_or(Error::Unavailable("R2 Sapling keys"))?;
                let e =
                    EnvelopeView::decode(s.envelope.as_ref().as_ref(), &c.round.config.domain())
                        .map_err(|_| Error::Invalid("R2 envelope framing"))?;
                let p = Payload::real_view(&e, &c.round)?;
                verify_borrowed(&e, k).map_err(|error| match error {
                    silk_sapling_f04::Error::Encoding(_) | silk_sapling_f04::Error::Crypto(_) => {
                        Error::Invalid("R2 Sapling verification")
                    }
                    _ => Error::Unavailable("R2 Sapling local capability"),
                })?;
                p
            };
            complete_before(deadline)?;
            payloads.push(p);
        }
        Ok(VerifiedR2Batch {
            payloads: payloads
                .try_into()
                .map_err(|_| Error::Unavailable("R2 payload count"))?,
            config: self.config,
            manifest: self.manifest,
            profile: self.profile,
            round: self.round,
        })
    }
}
/// Opaque verified payload preparation. No PUBLIC seal/release/export method.
/// Only the separately gated, explicitly unqualified lab exit can stage it.
pub struct VerifiedR2Batch {
    payloads: [Payload; 32],
    config: Digest,
    manifest: Digest,
    profile: Digest,
    round: u64,
}
impl VerifiedR2Batch {
    /// Fixed all-or-nothing payload count; not a producer-ready batch.
    pub const fn count(&self) -> usize {
        32
    }
    /// Exit-local volume already visible to B, never a source mapping.
    pub fn real_count(&self) -> usize {
        self.payloads.iter().filter(|p| p.is_real()).count()
    }
    #[cfg(feature = "functional-lab")]
    pub(crate) fn seal_for_lab(
        self,
        c: &PreparedR2Context<'_>,
    ) -> Result<crate::staging::StagedBatch> {
        if self.config != c.round.config.id()
            || self.manifest != c.round.manifest.id()
            || self.profile != c.profile.id()
            || self.round != c.round.manifest.round()
        {
            return Err(Error::Invalid("R2 verified staging context"));
        }
        // Preserve stage3, control and producer bytes; no legacy/raw-payload
        // conversion can manufacture this private verified owner.
        crate::staging::StagedBatch::seal(&c.round, self.payloads)
    }
}
fn complete_before(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Unavailable("R2 original completion deadline"))
    } else {
        Ok(())
    }
}
