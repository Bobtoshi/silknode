//! Complete co-signed round manifest. Signature validity is not finality/timeliness.
use crate::{Digest, Error, Result, config::SignedConfig, field, message, u32le, u64le};
use silk_f04_node::{auth::verify_role_signature, node::Node};
use silk_sapling_f04::codec::domain_hash;

/// Exact manifest with both Appendix C signatures checked against accepted C.
pub struct SignedManifest {
    bytes: [u8; 256],
    id: Digest,
    config: Digest,
    round: u64,
    domain: Digest,
}
impl SignedManifest {
    /// Check framing/context and then A followed by B signatures. The caller
    /// must first enforce its fixed phase and afterwards its durable one-M rule.
    /// # Errors
    /// Refuses framing/context/ED failure, without any journal/state mutation.
    pub fn verify(bytes: &[u8], config: &SignedConfig, round: u64) -> Result<Self> {
        let bytes: [u8; 256] = bytes
            .try_into()
            .map_err(|_| Error::Invalid("AUTH_ENCODING"))?;
        check_body(&bytes[..128], config, round)?;
        let signed = message("SilkNode-F0-round", &[&config.id(), &bytes[..128]]);
        verify_role_signature(&config.endpoints()[0].signing, &signed, &bytes[128..192])?;
        verify_role_signature(&config.endpoints()[1].signing, &signed, &bytes[192..256])?;
        Ok(Self {
            id: domain_hash("SilkNode-F0-manifest", &[&config.id(), &bytes]),
            config: config.id(),
            domain: config.domain(),
            round,
            bytes,
        })
    }
    /// Match the exact selected cut to a READY immutable locally verified node.
    /// An older eligible cut is allowed. A public fabricated Cut is not authority.
    /// # Errors
    /// Refuses unavailable node, foreign N, absent/orphaned/immature or mismatched cut.
    pub fn check_local_cut(&self, node: &Node) -> Result<()> {
        let state = node
            .state()
            .map_err(|_| Error::Unavailable("complete local cut history"))?;
        let index = u64le(&self.bytes, 52)?;
        if node.genesis().domain() != self.domain() || index > state.eligible_cut().index {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        let cut = usize::try_from(index)
            .ok()
            .and_then(|i| state.cuts().get(i))
            .ok_or(Error::Invalid("AUTH_SEMANTICS"))?;
        if cut.id != field::<32>(&self.bytes, 60)? || cut.root != field::<32>(&self.bytes, 92)? {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        Ok(())
    }
    /// Exact256 signed bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 256] {
        &self.bytes
    }
    /// Hash includes cfg and BOTH signature encodings.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Bound unsigned configuration hash.
    #[must_use]
    pub const fn config(&self) -> Digest {
        self.config
    }
    /// Exact round, not the caller's clock.
    #[must_use]
    pub const fn round(&self) -> u64 {
        self.round
    }
    /// Bound domain.
    #[must_use]
    pub const fn domain(&self) -> Digest {
        self.domain
    }
}

pub(crate) fn check_body(bytes: &[u8], config: &SignedConfig, round: u64) -> Result<()> {
    check_framing(bytes)?;
    check_context(bytes, config, round)
}
pub(crate) fn check_framing(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 128 || &bytes[..8] != b"SNRNDF03" || bytes[124..] != [0; 4] {
        return Err(Error::Invalid("AUTH_ENCODING"));
    }
    Ok(())
}
pub(crate) fn check_context(bytes: &[u8], config: &SignedConfig, round: u64) -> Result<()> {
    if bytes[8..40] != config.domain()
        || u32le(bytes, 40)? != config.cohort()
        || u64le(bytes, 44)? != round
        || !config.contains_round(round)
    {
        return Err(Error::Invalid("AUTH_CONTEXT_ROLE"));
    }
    Ok(())
}
