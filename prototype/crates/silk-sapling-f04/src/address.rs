//! Shared exact public payment descriptor, independent of node/wallet adapters.
use crate::{Digest, Error, Result, codec::domain_hash};
use sapling_crypto::PaymentAddress;

/// Encode the fixed234-character lowercase `SilkNode` descriptor.
/// Its checksum detects corruption, not recipient identity.
#[must_use]
pub fn encode(domain: &Digest, address: &PaymentAddress) -> String {
    let mut bytes = [0; 115];
    bytes[..8].copy_from_slice(b"SNADDR03");
    bytes[8..40].copy_from_slice(domain);
    bytes[40..83].copy_from_slice(&address.to_bytes());
    let checksum = domain_hash("SilkNode-F0-address", &[&bytes[..83]]);
    bytes[83..].copy_from_slice(&checksum);
    format!("sn3_{}", hex::encode(bytes))
}
/// Decode only canonical bytes under an independently accepted full domain.
/// # Errors
/// Refuses aliases, padding, case folding, changed checksum/domain or invalid keys.
pub fn decode(text: &str, domain: &Digest) -> Result<PaymentAddress> {
    if text.len() != 234
        || !text.starts_with("sn3_")
        || !text.as_bytes()[4..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return Err(Error::Encoding("payment descriptor framing/alphabet"));
    }
    let mut bytes = [0; 115];
    hex::decode_to_slice(&text[4..], &mut bytes)
        .map_err(|_| Error::Encoding("payment descriptor hex"))?;
    if &bytes[..8] != b"SNADDR03"
        || bytes[8..40] != *domain
        || bytes[83..] != domain_hash("SilkNode-F0-address", &[&bytes[..83]])
    {
        return Err(Error::Encoding(
            "payment descriptor version/domain/checksum",
        ));
    }
    let mut diversified = [0; 43];
    diversified.copy_from_slice(&bytes[40..83]);
    let address = PaymentAddress::from_bytes(&diversified)
        .ok_or(Error::Encoding("payment descriptor diversified key"))?;
    if encode(domain, &address) != text {
        return Err(Error::Encoding("noncanonical payment descriptor"));
    }
    Ok(address)
}
