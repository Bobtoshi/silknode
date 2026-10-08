//! Default-off IM3 transport correction candidate.
//! This removes R2's stable A-to-B ciphertext identifier only when the middle
//! boundary is independently operated. It is not omission accountability,
//! anonymity acceptance, runtime admission, or release authority.
use crate::{
    Digest, Error, Result,
    aip2_claim::{ClaimPinRetention, ClaimRole, ConsumedScope},
    aip2_profile::PreparedProfile,
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
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Exact co-signed IM3 route bytes. This is an additive transport profile,
/// never a replacement for signed consensus/configuration bytes.
pub const IM3_ROUTE_BYTES: usize = 384;
const ROUTE_BODY: usize = 192;

/// Independently selected middle identity/key pins. Route signatures cannot
/// substitute for the caller selecting a genuinely separate operator.
pub struct Im3RouteExpectations {
    /// Exact middle Ed25519 application identity selected out of band.
    pub middle_signing: Digest,
    /// Exact middle HPKE public key selected out of band.
    pub middle_hpke: Digest,
}

/// Exact A/M/B co-signed route linked to C and P. This proves byte agreement,
/// not operator independence, key erasure, endpoint qualification, or uptime.
pub struct PreparedIm3Route {
    bytes: [u8; IM3_ROUTE_BYTES],
    id: Digest,
    middle_hpke: Digest,
}
impl PreparedIm3Route {
    /// Verify fixed encoding, local C/P linkage, independently pinned middle
    /// keys, and strict A/B/M signatures in that order.
    pub fn verify(
        input: &[u8],
        config: &SignedConfig,
        profile: &PreparedProfile,
        expected: &Im3RouteExpectations,
    ) -> Result<Self> {
        let bytes: [u8; IM3_ROUTE_BYTES] = input
            .try_into()
            .map_err(|_| Error::Invalid("IM3 route length"))?;
        let a = config.hpke_keys()[0];
        let b = config.hpke_keys()[1];
        if &bytes[..8] != b"SNIM3R01"
            || bytes[8..40] != config.domain()
            || bytes[40..72] != config.id()
            || bytes[72..104] != profile.id()
            || bytes[104..108] != config.epoch().to_le_bytes()
            || bytes[108..112] != config.cohort().to_le_bytes()
            || bytes[112..144] != expected.middle_signing
            || bytes[144..176] != expected.middle_hpke
            || bytes[176..ROUTE_BODY] != [0; ROUTE_BODY - 176]
            || expected.middle_signing == [0; 32]
            || expected.middle_hpke == [0; 32]
            || expected.middle_signing == config.endpoints()[0].signing
            || expected.middle_signing == config.endpoints()[1].signing
            || expected.middle_hpke == a
            || expected.middle_hpke == b
            || a == b
        {
            return Err(Error::Invalid("IM3 route context/pins"));
        }
        let signed = message("SilkNode-AIP2IM3-route-sign", &[&bytes[..ROUTE_BODY]]);
        for (key, signature) in [
            (config.endpoints()[0].signing, &bytes[192..256]),
            (config.endpoints()[1].signing, &bytes[256..320]),
            (expected.middle_signing, &bytes[320..384]),
        ] {
            if !crate::aip2_signature(&key, &signed, signature) {
                return Err(Error::Invalid("IM3 route signatures"));
            }
        }
        Ok(Self {
            id: domain_hash("SilkNode-AIP2IM3-route", &[&bytes[..ROUTE_BODY]]),
            middle_hpke: expected.middle_hpke,
            bytes,
        })
    }
    /// Exact immutable route bytes, never admission or independence evidence.
    pub const fn bytes(&self) -> &[u8; IM3_ROUTE_BYTES] {
        &self.bytes
    }
    /// Identifier of the signed route body.
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Independently pinned middle HPKE public key.
    pub const fn middle_hpke(&self) -> Digest {
        self.middle_hpke
    }
}

/// Exact C/M/P/route binding for IM3 bytes. No schedule, endpoint, custody,
/// full-cohort, proof, or release authority is implied.
pub struct PreparedIm3Context<'a> {
    r2: PreparedR2Context<'a>,
    profile: &'a PreparedProfile,
    route: &'a PreparedIm3Route,
}
impl<'a> PreparedIm3Context<'a> {
    /// Bind an already verified route to the exact signed R2 context.
    pub fn new(
        config: &'a SignedConfig,
        manifest: &'a SignedManifest,
        profile: &'a PreparedProfile,
        vk_hash: Digest,
        route: &'a PreparedIm3Route,
    ) -> Result<Self> {
        let r2 = PreparedR2Context::new(config, manifest, profile, vk_hash)?;
        if route.bytes[8..40] != config.domain()
            || route.bytes[40..72] != config.id()
            || route.bytes[72..104] != profile.id()
            || route.bytes[104..108] != config.epoch().to_le_bytes()
            || route.bytes[108..112] != config.cohort().to_le_bytes()
        {
            return Err(Error::Invalid("IM3 context route"));
        }
        Ok(Self { r2, profile, route })
    }
    fn header(&self, stage: u8) -> Result<[u8; 64]> {
        if !(1..=3).contains(&stage) {
            return Err(Error::Invalid("IM3 stage"));
        }
        let mut header = self.r2.round.header(stage, 0)?;
        header[..8].copy_from_slice(b"SNMIX008");
        header[8..10].copy_from_slice(&8_u16.to_le_bytes());
        Ok(header)
    }
    fn info(&self, header: &[u8], recipient: &Digest) -> Vec<u8> {
        message(
            "SilkNode-AIP2IM3-HPKE",
            &[
                &self.r2.round.config.id(),
                &self.r2.round.manifest.id(),
                &self.profile.id(),
                &self.route.id(),
                header,
                recipient,
            ],
        )
    }
}

/// Version-separated IM3 A/M/B frame. Ciphertext authentication and complete
/// batch ownership remain separate from this fixed framing check.
pub struct PreparedIm3Frame(Box<[u8; FRAME_BYTES]>);
impl PreparedIm3Frame {
    /// Decode one exact IM3 stage and reject nonzero public padding.
    pub fn decode(bytes: &[u8], context: &PreparedIm3Context<'_>, stage: u8) -> Result<Self> {
        let end = match stage {
            1 => 4432,
            2 => 4320,
            3 => 4208,
            _ => return Err(Error::Invalid("IM3 stage")),
        };
        if bytes.len() != FRAME_BYTES
            || bytes[..64] != context.header(stage)?
            || bytes[end..].iter().any(|byte| *byte != 0)
        {
            return Err(Error::Invalid("IM3 frame context/version/padding"));
        }
        let mut retained = Box::new([0; FRAME_BYTES]);
        retained.copy_from_slice(bytes);
        Ok(Self(retained))
    }
    /// Exact immutable ciphertext bytes; not submission or timing authority.
    pub fn bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }
    pub(crate) fn encapsulation(&self) -> Digest {
        self.0[64..96].try_into().expect("32")
    }
}

fn seal(
    context: &PreparedIm3Context<'_>,
    header: &[u8; 64],
    recipient: &Digest,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| Error::Invalid("IM3 HPKE public key"))?;
    let (encapsulation, ciphertext) =
        single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &key,
            &context.info(header, recipient),
            plaintext,
            header,
            &mut random()?,
        )
        .map_err(|_| Error::Unavailable("IM3 HPKE seal"))?;
    let mut output = encapsulation.to_bytes().to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn open(
    context: &PreparedIm3Context<'_>,
    header: &[u8],
    recipient: &Digest,
    key: &HpkePrivate,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if X25519HkdfSha256::sk_to_pk(key).to_bytes().as_slice() != recipient {
        return Err(Error::Unavailable("IM3 wrong local HPKE key"));
    }
    let encapsulation = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
        ciphertext
            .get(..32)
            .ok_or(Error::Invalid("IM3 HPKE length"))?,
    )
    .map_err(|_| Error::Invalid("IM3 HPKE encapsulation"))?;
    let plaintext = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        key,
        &encapsulation,
        &context.info(header, recipient),
        &ciphertext[32..],
        header,
    )
    .map_err(|_| Error::Invalid("IM3 HPKE authentication"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Consume the one client scope and create fresh, independent B, middle, then
/// A HPKE layers. No ciphertext escapes before the claim is consumed.
pub fn seal_claimed_cell<P: ClaimPinRetention>(
    context: &PreparedIm3Context<'_>,
    claim: ConsumedScope<'_, P>,
    cell: &[u8; 4096],
) -> Result<PreparedIm3Frame> {
    if claim.binding() != context.profile.claim_binding(ClaimRole::Client)
        || claim.round() != context.r2.round.manifest.round()
        || claim.manifest() != context.r2.round.manifest.id()
        || claim.message() != context.r2.check_cell(cell)?
    {
        return Err(Error::Invalid("IM3 client receipt/cell"));
    }
    let h3 = context.header(3)?;
    let inner = seal(context, &h3, &context.r2.round.config.hpke_keys()[1], cell)?;
    if inner.len() != 4144 {
        return Err(Error::Unavailable("IM3 B inner size"));
    }
    let mut middle_plain = Zeroizing::new([0; 4208]);
    middle_plain[..64].copy_from_slice(&h3);
    middle_plain[64..].copy_from_slice(&inner);
    let h2 = context.header(2)?;
    let middle = seal(
        context,
        &h2,
        &context.route.middle_hpke,
        middle_plain.as_ref(),
    )?;
    if middle.len() != 4256 {
        return Err(Error::Unavailable("IM3 middle size"));
    }
    let mut a_plain = Zeroizing::new([0; 4320]);
    a_plain[..64].copy_from_slice(&h2);
    a_plain[64..].copy_from_slice(&middle);
    let h1 = context.header(1)?;
    let outer = seal(
        context,
        &h1,
        &context.r2.round.config.hpke_keys()[0],
        a_plain.as_ref(),
    )?;
    if outer.len() != 4368 {
        return Err(Error::Unavailable("IM3 A outer size"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..64].copy_from_slice(&h1);
    bytes[64..4432].copy_from_slice(&outer);
    PreparedIm3Frame::decode(&bytes, context, 1)
}

/// A removes only its own authenticated layer. The resulting stable identifier
/// belongs to the middle layer and is never presented to B.
pub fn open_at_a(
    context: &PreparedIm3Context<'_>,
    key: &HpkePrivate,
    frame: &PreparedIm3Frame,
) -> Result<PreparedIm3Frame> {
    PreparedIm3Frame::decode(frame.bytes(), context, 1)?;
    let plaintext = open(
        context,
        &frame.bytes()[..64],
        &context.r2.round.config.hpke_keys()[0],
        key,
        &frame.bytes()[64..4432],
    )?;
    if plaintext.len() != 4320 || plaintext[..64] != context.header(2)? {
        return Err(Error::Invalid("IM3 A plaintext"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..4320].copy_from_slice(&plaintext);
    PreparedIm3Frame::decode(&bytes, context, 2)
}

/// The independently operated middle removes its authenticated layer after A's
/// complete permutation, exposing B ciphertext bytes that A never observed.
#[cfg(test)]
pub(crate) fn open_at_middle(
    context: &PreparedIm3Context<'_>,
    key: &HpkePrivate,
    frame: &PreparedIm3Frame,
) -> Result<PreparedIm3Frame> {
    PreparedIm3Frame::decode(frame.bytes(), context, 2)?;
    let plaintext = open(
        context,
        &frame.bytes()[..64],
        &context.route.middle_hpke,
        key,
        &frame.bytes()[64..4320],
    )?;
    if plaintext.len() != 4208 || plaintext[..64] != context.header(3)? {
        return Err(Error::Invalid("IM3 middle plaintext"));
    }
    let mut bytes = [0; FRAME_BYTES];
    bytes[..4208].copy_from_slice(&plaintext);
    PreparedIm3Frame::decode(&bytes, context, 3)
}

fn permute_stage(
    context: &PreparedIm3Context<'_>,
    frames: &mut [PreparedIm3Frame; 32],
    stage: u8,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for frame in frames.iter() {
        PreparedIm3Frame::decode(frame.bytes(), context, stage)?;
        if !seen.insert(frame.encapsulation()) {
            return Err(Error::Invalid("IM3 duplicate encapsulation"));
        }
    }
    shuffle(frames)
}

/// A privately permutes an exact duplicate-free middle-ciphertext cohort.
pub fn permute_at_a(
    context: &PreparedIm3Context<'_>,
    frames: &mut [PreparedIm3Frame; 32],
) -> Result<()> {
    permute_stage(context, frames, 2)
}

/// The middle independently permutes an exact duplicate-free B-ciphertext cohort.
#[cfg(test)]
pub(crate) fn permute_at_middle(
    context: &PreparedIm3Context<'_>,
    frames: &mut [PreparedIm3Frame; 32],
) -> Result<()> {
    permute_stage(context, frames, 3)
}

/// Test-only B observation. Production B opening must remain behind one complete
/// batch, durable exit consumption, and all-32 membership verification.
#[cfg(test)]
pub(crate) fn open_at_b_for_test(
    context: &PreparedIm3Context<'_>,
    key: &HpkePrivate,
    frame: &PreparedIm3Frame,
) -> Result<Box<Zeroizing<[u8; 4096]>>> {
    PreparedIm3Frame::decode(frame.bytes(), context, 3)?;
    let plaintext = open(
        context,
        &frame.bytes()[..64],
        &context.r2.round.config.hpke_keys()[1],
        key,
        &frame.bytes()[64..4208],
    )?;
    let cell: [u8; 4096] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Invalid("IM3 B plaintext length"))?;
    let _ = context.r2.check_cell(&cell)?;
    Ok(Box::new(Zeroizing::new(cell)))
}
