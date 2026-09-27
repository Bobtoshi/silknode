//! Exact co-signed configuration and enrollment bytes; no connection or clock admission.
use crate::{Digest, Error, Result, field, message, u32le, u64le};
use silk_f04_node::auth::{admit_role_key, verify_role_signature};
use silk_sapling_f04::codec::domain_hash;

/// Exact unsigned configuration length.
pub const CONFIG_BODY: usize = 642;
/// Exact co-signed configuration length.
pub const CONFIG_BYTES: usize = 770;

/// Immutable endpoint bytes authenticated by the configuration, not DNS names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// IPv6, with IPv4 represented as IPv4-mapped IPv6.
    pub address: [u8; 16],
    /// TCP port.
    pub port: u16,
    /// Admitted pure Ed25519 application identity.
    pub signing: Digest,
    /// SHA256 of exact TLS `SubjectPublicKeyInfo` DER, not the leaf certificate.
    pub spki: Digest,
}

/// Verified exact signatures/context, NOT epoch admission, clock health, operator
/// independence or permission to replace an active configuration.
pub struct SignedConfig {
    bytes: [u8; CONFIG_BYTES],
    id: Digest,
    domain: Digest,
    cohort: u32,
    epoch: u32,
    endpoints: [Endpoint; 5],
    hpke: [Digest; 2],
    roster: Digest,
}
impl SignedConfig {
    /// Check exact framing, independently expected context/roots, all seven role
    /// keys in Appendix C order, A then B signatures, then body semantics.
    /// A stateful consumer must check phase admissibility BEFORE this function.
    /// # Errors
    /// Returns ordered framing/context/ED/semantic errors; no partial admission.
    pub fn verify(
        input: &[u8],
        domain: Digest,
        cohort: u32,
        epoch: u32,
        expected_roots: [Digest; 2],
    ) -> Result<Self> {
        let bytes: [u8; CONFIG_BYTES] = input
            .try_into()
            .map_err(|_| Error::Invalid("AUTH_ENCODING"))?;
        if &bytes[..8] != b"SNCFGF03" || bytes[640..642] != [0; 2] {
            return Err(Error::Invalid("AUTH_ENCODING"));
        }
        if bytes[8..40] != domain
            || u32le(&bytes, 40)? != cohort
            || u32le(&bytes, 44)? != epoch
            || bytes[64..96] != expected_roots[0]
            || bytes[96..128] != expected_roots[1]
        {
            return Err(Error::Invalid("AUTH_CONTEXT_ROLE"));
        }
        // Includes the duplicate endpoint A/B encodings in the specified order.
        for at in [64, 96, 210, 292, 374, 456, 538] {
            admit_role_key(&bytes[at..at + 32])?;
        }
        let signed = message("SilkNode-F0-config-sign", &[&bytes[..CONFIG_BODY]]);
        verify_role_signature(&expected_roots[0], &signed, &bytes[642..706])?;
        verify_role_signature(&expected_roots[1], &signed, &bytes[706..770])?;
        let first = u64::from(epoch) * 2880;
        if u64le(&bytes, 48)? != first
            || u64le(&bytes, 56)? != first + 2880
            || u32le(&bytes, 634)? != 500
            || bytes[638..640] != [8, 32]
            || bytes[210..242] != expected_roots[0]
            || bytes[292..324] != expected_roots[1]
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        let endpoint = |at| -> Result<Endpoint> {
            Ok(Endpoint {
                address: field(&bytes, at)?,
                port: u16::from_le_bytes(field(&bytes, at + 16)?),
                signing: field(&bytes, at + 18)?,
                spki: field(&bytes, at + 50)?,
            })
        };
        let endpoints = [
            endpoint(192)?,
            endpoint(274)?,
            endpoint(356)?,
            endpoint(438)?,
            endpoint(520)?,
        ];
        Ok(Self {
            id: domain_hash("SilkNode-F0-config", &[&bytes[..CONFIG_BODY]]),
            hpke: [field(&bytes, 128)?, field(&bytes, 160)?],
            roster: field(&bytes, 602)?,
            bytes,
            domain,
            cohort,
            epoch,
            endpoints,
        })
    }
    /// Exact co-signed bytes, unchanged.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; CONFIG_BYTES] {
        &self.bytes
    }
    /// Hash of unsigned642-byte C only.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Independently expected ledger domain.
    #[must_use]
    pub const fn domain(&self) -> Digest {
        self.domain
    }
    /// Fixed cohort.
    #[must_use]
    pub const fn cohort(&self) -> u32 {
        self.cohort
    }
    /// Fixed epoch.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }
    /// A, B, P0, P1, P2 endpoint order.
    #[must_use]
    pub const fn endpoints(&self) -> &[Endpoint; 5] {
        &self.endpoints
    }
    /// Public A then B HPKE keys. These are not Ed25519 encodings.
    #[must_use]
    pub const fn hpke_keys(&self) -> [Digest; 2] {
        self.hpke
    }
    /// Configured range membership only, not a clock observation.
    #[must_use]
    pub const fn contains_round(&self, round: u64) -> bool {
        round / 2880 == self.epoch as u64
    }
    /// Fixed roster commitment. Does not establish unique honest people.
    #[must_use]
    pub const fn roster_hash(&self) -> Digest {
        self.roster
    }
}

/// Exactly32 sorted unique admission-token hashes. Original tokens/source
/// associations must remain private at A and their respective clients.
pub struct Roster {
    hashes: [Digest; 32],
    config: Digest,
}
impl Roster {
    /// Validate ordering/uniqueness and the signed commitment before enrollment.
    /// # Errors
    /// Refuses unsorted/duplicate hashes or a foreign commitment.
    pub fn verify(hashes: [Digest; 32], config: &SignedConfig) -> Result<Self> {
        if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        let mut flat = [0; 1024];
        for (slot, hash) in hashes.iter().enumerate() {
            flat[slot * 32..(slot + 1) * 32].copy_from_slice(hash);
        }
        if domain_hash(
            "SilkNode-F0-roster",
            &[
                &config.domain,
                &config.cohort.to_le_bytes(),
                &config.epoch.to_le_bytes(),
                &flat,
            ],
        ) != config.roster_hash()
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        Ok(Self {
            hashes,
            config: config.id(),
        })
    }
    /// Check exact128-byte join and membership. Returns only a token hash;
    /// concurrent session uniqueness and epoch connection admission are stateful.
    /// # Errors
    /// Refuses bad framing/context or an unenrolled token.
    pub fn verify_join(&self, bytes: &[u8], config: &SignedConfig) -> Result<Digest> {
        if bytes.len() != 128 || &bytes[..8] != b"SNJOIN03" || bytes[80..] != [0; 48] {
            return Err(Error::Invalid("AUTH_ENCODING"));
        }
        if self.config != config.id()
            || bytes[8..40] != config.domain
            || u32le(bytes, 40)? != config.cohort
            || u32le(bytes, 44)? != config.epoch
        {
            return Err(Error::Invalid("AUTH_CONTEXT_ROLE"));
        }
        let token = domain_hash("SilkNode-F0-token", &[&bytes[48..80]]);
        if self.hashes.binary_search(&token).is_err() {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        Ok(token)
    }
    /// Derive the fixed input slot from a verified token hash, never arrival order.
    /// # Errors
    /// Refuses a hash absent from this configuration's committed roster.
    pub fn slot(&self, token: &Digest) -> Result<u8> {
        self.hashes
            .binary_search(token)
            .ok()
            .and_then(|slot| u8::try_from(slot).ok())
            .ok_or(Error::Invalid("unadmitted input slot"))
    }
}
