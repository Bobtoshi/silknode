//! Fixed data cells and genuine standard HPKE layers. No scheduling/readiness authority.
use crate::{
    Digest, Error, Result, config::SignedConfig, field, manifest::SignedManifest, message, u32le,
    u64le,
};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal_with_rng,
};
use rand_chacha_10::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use rand_core_06::{OsRng, RngCore};
use silk_sapling_f04::codec::{ENVELOPE_BYTES, Envelope, EnvelopeView};
use zeroize::Zeroizing;

/// Fixed public wire frame size.
pub const FRAME_BYTES: usize = 8192;
/// Exact suite private key. Keep in its own relay's secret domain.
pub type HpkePrivate = <X25519HkdfSha256 as Kem>::PrivateKey;

/// Config/manifest byte binding only; separately validate the local mature cut,
/// immutable phase/clock, journal and one-manifest rule before using a real round.
pub struct RoundContext<'a> {
    pub(crate) config: &'a SignedConfig,
    pub(crate) manifest: &'a SignedManifest,
}
impl<'a> RoundContext<'a> {
    /// Bind one signature-checked manifest to its exact configuration.
    /// # Errors
    /// Refuses a foreign configuration/domain or epoch.
    pub fn new(config: &'a SignedConfig, manifest: &'a SignedManifest) -> Result<Self> {
        let config_hash = config.id();
        if config_hash != manifest.config()
            || config.domain() != manifest.domain()
            || !config.contains_round(manifest.round())
        {
            return Err(Error::Invalid("data context"));
        }
        Ok(Self { config, manifest })
    }
    pub(crate) fn header(&self, stage: u8, index: u32) -> Result<[u8; 64]> {
        if !(1..=3).contains(&stage) || (stage < 3 && index != 0) || index >= 32 {
            return Err(Error::Invalid("data stage/index"));
        }
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(b"SNMIX003");
        bytes[8..10].copy_from_slice(&3_u16.to_le_bytes());
        bytes[10] = stage;
        bytes[12..20].copy_from_slice(&self.manifest.round().to_le_bytes());
        bytes[20..52].copy_from_slice(&self.config.domain());
        bytes[52..56].copy_from_slice(&self.config.cohort().to_le_bytes());
        bytes[56..60].copy_from_slice(&self.config.epoch().to_le_bytes());
        bytes[60..64].copy_from_slice(&index.to_le_bytes());
        Ok(bytes)
    }
    fn info(&self, header: &[u8], recipient: &Digest) -> Vec<u8> {
        message(
            "SilkNode-F0-HPKE",
            &[&self.config.id(), &self.manifest.id(), header, recipient],
        )
    }
}

/// Fixed context/framing-checked cell, not HPKE/proof/readiness verification.
pub struct Frame(Box<[u8; FRAME_BYTES]>);
impl Frame {
    /// Check exact scheduled stage/index/header and unencrypted zero padding.
    /// # Errors
    /// Refuses any length/context/stage/index/reserved/padding mismatch.
    pub fn decode(bytes: &[u8], context: &RoundContext<'_>, stage: u8, index: u32) -> Result<Self> {
        if bytes.len() != FRAME_BYTES || bytes[..64] != context.header(stage, index)? {
            return Err(Error::Invalid("data frame context/framing"));
        }
        let payload_end = match stage {
            1 => 4720,
            2 => 4208,
            3 => FRAME_BYTES,
            _ => return Err(Error::Invalid("data stage")),
        };
        if bytes[payload_end..].iter().any(|byte| *byte != 0) {
            return Err(Error::Invalid("data frame padding"));
        }
        let mut retained = Box::new([0; FRAME_BYTES]);
        retained.copy_from_slice(bytes);
        Ok(Self(retained))
    }
    /// Exact public ciphertext frame. Partial writes must retain these same bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }
    /// HPKE encapsulation for a caller's bounded round duplicate set.
    /// # Errors
    /// Stage3 uses AEAD, not HPKE, and has no encapsulation.
    pub fn encapsulation(&self) -> Result<Digest> {
        if self.0[10] == 3 {
            return Err(Error::Invalid("stage3 has no encapsulation"));
        }
        field(self.0.as_slice(), 64)
    }
}

/// One private exit-view cell. Standard envelope framing is NOT Sapling validity.
/// No Debug/Clone or persistence; wrapper-owned payload bytes are wiped on drop.
pub struct Payload {
    kind: u8,
    bytes: Box<Zeroizing<[u8; ENVELOPE_BYTES]>>,
}
impl Payload {
    /// Build one IM3 choice with the same allocation, full payload copy and
    /// framing/context/zero scans for either kind. Invalid offered bytes fail
    /// silently at the owner; they are never replaced with another Cell.
    /// This is fixed source work, not a machine-code constant-time guarantee.
    pub fn client_choice(
        offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
        context: &RoundContext<'_>,
    ) -> Result<Self> {
        let kind = u8::from(offer.is_some());
        let cover = Zeroizing::new([0; ENVELOPE_BYTES]);
        let input = offer.as_ref().unwrap_or(&cover);
        let mut bytes = Box::new(Zeroizing::new([0; ENVELOPE_BYTES]));
        bytes.copy_from_slice(input.as_ref());
        let payload = Self { kind, bytes };
        payload.validate(context)?;
        Ok(payload)
    }
    /// Valid fixed zero cover, not an additional admitted/honest participant.
    #[must_use]
    pub fn cover() -> Self {
        Self {
            kind: 0,
            bytes: Box::new(Zeroizing::new([0; ENVELOPE_BYTES])),
        }
    }
    /// Bind an already signed ordinary envelope to the exact shared manifest.
    /// The wallet must durably mark exposure BEFORE giving these bytes to transport.
    /// # Errors
    /// Refuses a different N/c/Kc/Rc; cryptographic verification is separate.
    pub fn real(envelope: &Envelope, context: &RoundContext<'_>) -> Result<Self> {
        Self::real_from_bytes(envelope.bytes(), context)
    }
    /// Bind a borrowed envelope without making an unwiped owned codec copy.
    /// Exposure durability and explicit submission choice remain wallet duties.
    /// # Errors
    /// Refuses a different N/c/Kc/Rc; this is not proof verification.
    pub fn real_view(envelope: &EnvelopeView<'_>, context: &RoundContext<'_>) -> Result<Self> {
        Self::real_from_bytes(envelope.bytes(), context)
    }
    fn check_real(bytes: &[u8], context: &RoundContext<'_>) -> Result<()> {
        let envelope = EnvelopeView::decode(bytes, &context.config.domain())
            .map_err(|_| Error::Invalid("payload envelope framing"))?;
        if envelope.domain() != context.config.domain()
            || envelope.cut_index() != u64le(context.manifest.bytes(), 52)?
            || envelope.cut_id() != field::<32>(context.manifest.bytes(), 60)?
            || envelope.anchor() != field::<32>(context.manifest.bytes(), 92)?
        {
            return Err(Error::Invalid("payload manifest cut"));
        }
        Ok(())
    }
    fn real_from_bytes(input: &[u8], context: &RoundContext<'_>) -> Result<Self> {
        Self::check_real(input, context)?;
        let mut bytes = Box::new(Zeroizing::new([0; ENVELOPE_BYTES]));
        bytes.copy_from_slice(input);
        Ok(Self { kind: 1, bytes })
    }
    pub(crate) fn validate(&self, context: &RoundContext<'_>) -> Result<()> {
        let bytes = self.bytes.as_ref().as_ref();
        let framed = EnvelopeView::decode(bytes, &context.config.domain()).is_ok();
        let cut = fixed_equal(&bytes[44..52], &context.manifest.bytes()[52..60])
            & fixed_equal(&bytes[52..84], &context.manifest.bytes()[60..92])
            & fixed_equal(&bytes[1798..1830], &context.manifest.bytes()[92..124]);
        let zero = bytes.iter().fold(0_u8, |all, byte| all | byte) == 0;
        let valid = ((self.kind == 0) & zero) | ((self.kind == 1) & framed & cut);
        if !valid {
            return Err(Error::Invalid("payload kind/framing/manifest cut"));
        }
        Ok(())
    }
    pub(crate) fn copy_prepared_cell(&self, cell: &mut [u8; 4096]) {
        cell[8] = self.kind;
        cell[416..3206].copy_from_slice(self.bytes.as_ref().as_ref());
    }
    /// Exit-visible real/cover class. Never attach source metadata to this result.
    #[must_use]
    pub const fn is_real(&self) -> bool {
        self.kind == 1
    }
    /// Exact signed real bytes or no payload for cover. B can already see these
    /// even if a subsequent round decision aborts; staging cannot erase its view.
    #[must_use]
    pub fn real_bytes(&self) -> Option<&[u8; ENVELOPE_BYTES]> {
        (self.kind == 1).then_some(&self.bytes)
    }
    pub(crate) fn plaintext(&self, context: &RoundContext<'_>) -> Zeroizing<[u8; 4096]> {
        let mut bytes = Zeroizing::new([0; 4096]);
        bytes[..8].copy_from_slice(b"SNPAYF03");
        bytes[8] = self.kind;
        bytes[16..24].copy_from_slice(&context.manifest.round().to_le_bytes());
        bytes[24..56].copy_from_slice(&context.config.domain());
        bytes[56..60].copy_from_slice(&context.config.cohort().to_le_bytes());
        bytes[64..2854].copy_from_slice(self.bytes.as_ref().as_ref());
        bytes
    }
    pub(crate) fn decode(bytes: &[u8], context: &RoundContext<'_>) -> Result<Self> {
        if bytes.len() != 4096
            || &bytes[..8] != b"SNPAYF03"
            || bytes[8] > 1
            || bytes[9..16] != [0; 7]
            || bytes[60..64] != [0; 4]
            || bytes[2854..].iter().any(|byte| *byte != 0)
            || u64le(bytes, 16)? != context.manifest.round()
            || bytes[24..56] != context.config.domain()
            || u32le(bytes, 56)? != context.config.cohort()
        {
            return Err(Error::Invalid("payload framing/context"));
        }
        if bytes[8] == 0 {
            if bytes[64..2854] != [0; ENVELOPE_BYTES] {
                return Err(Error::Invalid("nonzero cover payload"));
            }
            Ok(Self::cover())
        } else {
            Self::real_from_bytes(&bytes[64..2854], context)
        }
    }
}

fn fixed_equal(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub(crate) fn random() -> Result<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| Error::Unavailable("OS entropy"))?;
    Ok(ChaCha20Rng::from_seed(*seed))
}
/// Fresh independent OS-seeded epoch keypair for ONE relay, not custody admission.
/// Wrapper seeds are wiped; this does not assert erasure of every upstream copy.
/// # Errors
/// Refuses OS entropy failure without a deterministic fallback.
pub fn generate_hpke_key() -> Result<(HpkePrivate, Digest)> {
    let (secret, public) = X25519HkdfSha256::gen_keypair_with_rng(&mut random()?);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(public.to_bytes().as_slice());
    Ok((secret, bytes))
}
fn seal(
    context: &RoundContext<'_>,
    header: &[u8; 64],
    recipient: &Digest,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| Error::Invalid("HPKE public key"))?;
    let (enc, cipher) =
        single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &key,
            &context.info(header, recipient),
            plain,
            header,
            &mut random()?,
        )
        .map_err(|_| Error::Unavailable("HPKE seal"))?;
    let mut output = Vec::with_capacity(32 + cipher.len());
    output.extend_from_slice(enc.to_bytes().as_slice());
    output.extend_from_slice(&cipher);
    Ok(output)
}
fn open(
    context: &RoundContext<'_>,
    header: &[u8],
    recipient: &Digest,
    key: &HpkePrivate,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if X25519HkdfSha256::sk_to_pk(key).to_bytes().as_slice() != recipient {
        return Err(Error::Unavailable("wrong local HPKE role key"));
    }
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
        bytes.get(..32).ok_or(Error::Invalid("HPKE length"))?,
    )
    .map_err(|_| Error::Invalid("HPKE encapsulation"))?;
    let plain = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        key,
        &enc,
        &context.info(header, recipient),
        &bytes[32..],
        header,
    )
    .map_err(|_| Error::Invalid("HPKE authentication"))?;
    Ok(Zeroizing::new(plain))
}

/// Client's fresh double HPKE encapsulation, identically shaped for real/cover.
/// # Errors
/// Refuses context/entropy/crypto failure. Does not retry or submit any bytes.
pub fn client_cell(context: &RoundContext<'_>, payload: &Payload) -> Result<Frame> {
    // Recheck a previously constructed real Payload against this round context.
    payload.validate(context)?;
    let h2 = context.header(2, 0)?;
    let sealed_b = seal(
        context,
        &h2,
        &context.config.hpke_keys()[1],
        payload.plaintext(context).as_ref(),
    )?;
    if sealed_b.len() != 4144 {
        return Err(Error::Unavailable("B HPKE size"));
    }
    let mut a_plain = Zeroizing::new([0; 4608]);
    a_plain[..64].copy_from_slice(&h2);
    a_plain[64..4208].copy_from_slice(&sealed_b);
    let h1 = context.header(1, 0)?;
    let sealed_a = seal(
        context,
        &h1,
        &context.config.hpke_keys()[0],
        a_plain.as_ref(),
    )?;
    if sealed_a.len() != 4656 {
        return Err(Error::Unavailable("A HPKE size"));
    }
    let mut frame = [0; FRAME_BYTES];
    frame[..64].copy_from_slice(&h1);
    frame[64..4720].copy_from_slice(&sealed_a);
    Frame::decode(&frame, context, 1, 0)
}

/// A removes only its HPKE layer, producing a source-label-free stage2 frame.
/// Round/session uniqueness and the input-cutoff barrier remain required.
/// # Errors
/// Refuses wrong context, local key, HPKE authentication or inner header/padding.
pub fn open_a(context: &RoundContext<'_>, key: &HpkePrivate, frame: &Frame) -> Result<Frame> {
    let checked = Frame::decode(frame.bytes(), context, 1, 0)?;
    let plain = open(
        context,
        &checked.bytes()[..64],
        &context.config.hpke_keys()[0],
        key,
        &checked.bytes()[64..4720],
    )?;
    if plain.len() != 4608
        || plain[..64] != context.header(2, 0)?
        || plain[4208..].iter().any(|b| *b != 0)
    {
        return Err(Error::Invalid("A plaintext context/padding"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..4208].copy_from_slice(&plain[..4208]);
    Frame::decode(&bytes, context, 2, 0)
}
/// B recovers its private exit view before any release decision. No origin proof.
/// # Errors
/// Refuses malformed/foreign frames, wrong key, failed HPKE or invalid payload.
pub fn open_b(context: &RoundContext<'_>, key: &HpkePrivate, frame: &Frame) -> Result<Payload> {
    let checked = Frame::decode(frame.bytes(), context, 2, 0)?;
    let plain = open(
        context,
        &checked.bytes()[..64],
        &context.config.hpke_keys()[1],
        key,
        &checked.bytes()[64..4208],
    )?;
    Payload::decode(&plain, context)
}

pub(crate) fn shuffle<T>(values: &mut [T; 32]) -> Result<()> {
    let mut rng = random()?;
    for i in (1..32).rev() {
        let bound = (i + 1) as u64;
        let threshold = bound.wrapping_neg() % bound;
        let chosen = loop {
            let candidate = rng.next_u64();
            if candidate >= threshold {
                break usize::try_from(candidate % bound)
                    .map_err(|_| Error::Unavailable("permutation index"))?;
            }
        };
        values.swap(i, chosen);
    }
    Ok(())
}

/// A's independent uniform32-cell permutation after source metadata is stripped.
///
/// Input records cannot carry source/session labels; actual transport ownership
/// still needs a separate single-coordinator/single-queue implementation.
/// # Errors
/// Refuses non-stage2, foreign or duplicate encapsulations and entropy failure.
pub fn permute_stage2(context: &RoundContext<'_>, frames: &mut [Frame; 32]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for frame in frames.iter() {
        let checked = Frame::decode(frame.bytes(), context, 2, 0)?;
        if !seen.insert(checked.encapsulation()?) {
            return Err(Error::Invalid("duplicate B encapsulation"));
        }
    }
    shuffle(frames)
}
