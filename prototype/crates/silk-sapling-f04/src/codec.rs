//! Exact F0.4 framing. Decoding is not proof verification or context activation.

use crate::{Digest, Error, Result};
use sha2::{Digest as _, Sha256};

/// Exact ordinary envelope length.
pub const ENVELOPE_BYTES: usize = 2790;
/// Signed economic-effect prefix length.
pub const EFFECT_BYTES: usize = 1830;
/// Exact output description length (including the value commitment).
pub const OUTPUT_BYTES: usize = 756;
/// Canonical recovery entry length (excluding the value commitment).
pub const RECOVERY_BYTES: usize = 724;
/// Accepted immutable F0.4 rules, not the later implementation-contract digest.
pub const RULES_ID: Digest = [
    0x0a, 0x06, 0x63, 0x1f, 0x93, 0x8c, 0xd7, 0xce, 0xfe, 0xd9, 0xd5, 0x65, 0x50, 0xe2, 0xd7, 0xbf,
    0xde, 0x3c, 0x40, 0xda, 0xaa, 0x1a, 0xaa, 0xf8, 0xc4, 0x27, 0x2b, 0xba, 0x37, 0xb3, 0x13, 0x89,
];

/// SHA-256 over the one-byte-length application domain and unframed parts.
///
/// # Panics
/// Panics for a programmer-supplied non-ASCII label or one exceeding 255 bytes.
#[must_use]
pub fn domain_hash(label: &'static str, parts: &[&[u8]]) -> Digest {
    assert!(label.is_ascii() && label.len() < 256);
    let mut h = Sha256::new();
    h.update([u8::try_from(label.len()).expect("fixed domain")]);
    h.update(label.as_bytes());
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// Counted big-endian carriage hashing, deliberately distinct from D(label).
#[must_use]
pub fn carriage_hash(label: &'static str, parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    h.update((label.len() as u64).to_be_bytes());
    h.update(label.as_bytes());
    h.update((parts.len() as u64).to_be_bytes());
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Structurally valid static context. Genesis derivation and explicit operator
/// acceptance must additionally be established before using it as node authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    bytes: [u8; 256],
    domain: Digest,
}

impl Context {
    /// Reject noncanonical/unknown profiles. Does not accept a peer-supplied genesis.
    ///
    /// # Errors
    /// Returns `Encoding` for wrong lengths, versions, rules, activation or reserved bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 256] = bytes
            .try_into()
            .map_err(|_| Error::Encoding("context length"))?;
        if &bytes[..8] != b"SNCTX003"
            || bytes[8..12] != [3, 0, 0, 0]
            || bytes[204..212] != [0; 8]
            || bytes[212..220] != [3, 0, 4, 0, 1, 0, 0, 0]
            || bytes[220..252] != RULES_ID
            || bytes[252..] != [0; 4]
        {
            return Err(Error::Encoding("context version/rules/reserved/activation"));
        }
        let domain = domain_hash("SilkNode-F0-context", &[&bytes]);
        Ok(Self { bytes, domain })
    }
    /// Full canonical context bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 256] {
        &self.bytes
    }
    /// Network/genesis/static-branch/activation/rules-bound N.
    #[must_use]
    pub const fn domain(&self) -> Digest {
        self.domain
    }
}

/// Allocation-free envelope framing view. Does not verify proofs or own plaintext.
pub struct EnvelopeView<'a> {
    bytes: &'a [u8; ENVELOPE_BYTES],
}

impl<'a> EnvelopeView<'a> {
    /// Check exact length, versions, counts, fee, context and distinct nullifiers.
    /// This performs no elliptic-curve operations; suitable before work checking.
    ///
    /// # Errors
    /// Returns `Encoding` for a noncanonical frame or mismatched context.
    pub fn decode(bytes: &'a [u8], expected_domain: &Digest) -> Result<Self> {
        let bytes: &'a [u8; ENVELOPE_BYTES] = bytes
            .try_into()
            .map_err(|_| Error::Encoding("envelope length"))?;
        if &bytes[..8] != b"SNPRV003" || bytes[8..12] != [3, 0, 0, 0] {
            return Err(Error::Encoding("envelope version/reserved"));
        }
        if &bytes[12..44] != expected_domain {
            return Err(Error::Encoding("envelope context"));
        }
        if bytes[84] != 2 || bytes[277] != 2 || bytes[1790..1798] != 1_i64.to_le_bytes() {
            return Err(Error::Encoding("envelope counts/fee"));
        }
        if bytes[117..149] == bytes[213..245] {
            return Err(Error::Encoding("equal nullifiers"));
        }
        Ok(Self { bytes })
    }
    /// Original borrowed bytes, without a retained allocation.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8; ENVELOPE_BYTES] {
        self.bytes
    }
    /// Signed context N.
    #[must_use]
    pub fn domain(&self) -> Digest {
        field(self.bytes, 12)
    }
    /// Signed public cut ordinal.
    #[must_use]
    pub fn cut_index(&self) -> u64 {
        u64::from_le_bytes(field(self.bytes, 44))
    }
    /// Signed complete cut digest.
    #[must_use]
    pub fn cut_id(&self) -> Digest {
        field(self.bytes, 52)
    }
    /// Signed Sapling anchor.
    #[must_use]
    pub fn anchor(&self) -> Digest {
        field(self.bytes, 1798)
    }
}

/// Framed but not cryptographically verified envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    bytes: Box<[u8; ENVELOPE_BYTES]>,
}

impl Envelope {
    /// Retain an owned envelope after the identical allocation-free framing check.
    /// # Errors
    /// Returns `Encoding` for a noncanonical frame or mismatched context.
    pub fn decode(bytes: &[u8], expected_domain: &Digest) -> Result<Self> {
        let view = EnvelopeView::decode(bytes, expected_domain)?;
        Ok(Self {
            bytes: view
                .bytes()
                .to_vec()
                .into_boxed_slice()
                .try_into()
                .map_err(|_| Error::Encoding("envelope length"))?,
        })
    }
    /// Exact retained bytes; proof changes cannot inherit another representation's validity.
    #[must_use]
    pub fn bytes(&self) -> &[u8; ENVELOPE_BYTES] {
        &self.bytes
    }
    /// Context N carried in the signed bytes.
    #[must_use]
    pub fn domain(&self) -> Digest {
        field(&self.bytes[..], 12)
    }
    /// Public cut ordinal.
    #[must_use]
    pub fn cut_index(&self) -> u64 {
        u64::from_le_bytes(field(&self.bytes[..], 44))
    }
    /// Complete prefix-bound cut digest, not just a note root.
    #[must_use]
    pub fn cut_id(&self) -> Digest {
        field(&self.bytes[..], 52)
    }
    /// Common Sapling anchor.
    #[must_use]
    pub fn anchor(&self) -> Digest {
        field(&self.bytes[..], 1798)
    }
    /// Both nullifiers, including any standard zero-value dummy input.
    #[must_use]
    pub fn nullifiers(&self) -> [Digest; 2] {
        [field(&self.bytes[..], 117), field(&self.bytes[..], 213)]
    }
    /// Both recovery entries, in committed slot order.
    #[must_use]
    pub fn recovery(&self) -> [[u8; RECOVERY_BYTES]; 2] {
        [field(&self.bytes[..], 310), field(&self.bytes[..], 1066)]
    }
    /// Both public output value commitments in the SAME slot order as recovery.
    /// Decoding alone grants no proof or canonical acceptance authority.
    #[must_use]
    pub fn output_value_commitments(&self) -> [Digest; 2] {
        [field(&self.bytes[..], 278), field(&self.bytes[..], 1034)]
    }
    /// Economic identifier excludes authorizations, but is not a verification-cache key.
    #[must_use]
    pub fn effect_id(&self) -> Digest {
        domain_hash("SilkNode-F0-effect", &[&self.bytes[..EFFECT_BYTES]])
    }
    /// Standard Sapling signing APIs consume this exact 32-byte message.
    #[must_use]
    pub fn sighash(&self) -> Digest {
        domain_hash("SilkNode-F0-sign", &[&self.bytes[..EFFECT_BYTES]])
    }
    /// Exact full-representation identifier for bounded positive caches.
    #[must_use]
    pub fn envelope_id(&self) -> Digest {
        domain_hash("SilkNode-F0-envelope", &[&self.bytes[..]])
    }
}

pub(crate) fn field<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N]
        .try_into()
        .expect("validated fixed layout")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn framed() -> [u8; ENVELOPE_BYTES] {
        let mut b = [0; ENVELOPE_BYTES];
        b[..8].copy_from_slice(b"SNPRV003");
        b[8] = 3;
        b[84] = 2;
        b[277] = 2;
        b[213] = 1;
        b[1790] = 1;
        b
    }
    #[test]
    fn framing_is_exact_and_not_a_crypto_claim() {
        let b = framed();
        let e = Envelope::decode(&b, &[0; 32]).unwrap();
        let view = EnvelopeView::decode(&b, &[0; 32]).unwrap();
        assert_eq!(view.bytes().as_ptr(), b.as_ptr());
        assert_eq!(view.domain(), e.domain());
        assert_eq!(view.cut_index(), e.cut_index());
        assert_eq!(view.cut_id(), e.cut_id());
        assert_eq!(view.anchor(), e.anchor());
        assert_eq!(e.bytes(), &b);
        for at in [0, 8, 9, 10, 11, 12, 84, 277, 1790, 1797] {
            let mut bad = b;
            bad[at] ^= 1;
            assert!(Envelope::decode(&bad, &[0; 32]).is_err(), "{at}");
            assert_eq!(
                Envelope::decode(&bad, &[0; 32]).err().unwrap().to_string(),
                EnvelopeView::decode(&bad, &[0; 32])
                    .err()
                    .unwrap()
                    .to_string()
            );
        }
        assert!(Envelope::decode(&b[..2789], &[0; 32]).is_err());
        let mut trailing = b.to_vec();
        trailing.push(0);
        assert!(Envelope::decode(&trailing, &[0; 32]).is_err());
        let mut equal = b;
        equal[213] = 0;
        assert!(Envelope::decode(&equal, &[0; 32]).is_err());
    }
    #[test]
    fn representation_identity_does_not_change_economic_identity() {
        let b = framed();
        let e = Envelope::decode(&b, &[0; 32]).unwrap();
        // Independently calculated with Python hashlib from literal F0.4 offsets,
        // without calling these Rust encoders or hash helpers.
        assert_eq!(
            hex::encode(e.effect_id()),
            "114cf0788c61775742c748167299ea8871d49a3d6fa40b49e14c4ad9ca0d0c9b"
        );
        assert_eq!(
            hex::encode(e.sighash()),
            "d2d0046fff7950f0cac398c26e660a1960151c81e4b3cb5fee781966cf0cd150"
        );
        assert_eq!(
            hex::encode(e.envelope_id()),
            "1719236f17de50b1900f3c6d6523b9ef9052d1679801c29a05c1309e619dcdd4"
        );
        for at in [1830, 2214, 2342, 2726, 2789] {
            let mut alternative = b;
            alternative[at] ^= 1;
            let a = Envelope::decode(&alternative, &[0; 32]).unwrap();
            assert_eq!(e.effect_id(), a.effect_id());
            assert_eq!(e.sighash(), a.sighash());
            assert_ne!(e.envelope_id(), a.envelope_id());
        }
        for at in [44, 52, 278, 310, 1798] {
            let mut altered = b;
            altered[at] ^= 1;
            let a = Envelope::decode(&altered, &[0; 32]).unwrap();
            assert_ne!(e.effect_id(), a.effect_id());
            assert_ne!(e.sighash(), a.sighash());
        }
    }
    #[test]
    fn unknown_profile_and_nonzero_activation_reject() {
        let mut b = [0; 256];
        b[..8].copy_from_slice(b"SNCTX003");
        b[8] = 3;
        b[212..220].copy_from_slice(&[3, 0, 4, 0, 1, 0, 0, 0]);
        b[220..252].copy_from_slice(&RULES_ID);
        let c = Context::decode(&b).unwrap();
        assert_eq!(
            hex::encode(c.domain()),
            "7c6119700c4cfad457ee90f56670c9995b468ef6003d6c4a33752ba5bdacf9c9"
        );
        for at in [8, 10, 204, 212, 214, 216, 218, 220, 252] {
            let mut bad = b;
            bad[at] ^= 1;
            assert!(Context::decode(&bad).is_err());
        }
        for at in [12, 44, 76, 108, 140, 172] {
            let mut other = b;
            other[at] ^= 1;
            assert_ne!(c.domain(), Context::decode(&other).unwrap().domain());
        }
    }
}
