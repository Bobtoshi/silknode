//! Exact SilkNode-only public payment descriptor. No permissive Zcash/address alias.
use crate::{Digest, Error, Result};
use sapling_crypto::PaymentAddress;
#[cfg(test)]
use silk_sapling_f04::codec::domain_hash;

/// Encode the specified F0.4 234-character lowercase descriptor.
/// The checksum detects corruption; it does not authenticate the recipient.
#[must_use]
pub fn encode(domain: &Digest, address: &PaymentAddress) -> String {
    silk_sapling_f04::address::encode(domain, address)
}

/// Decode only exact canonical bytes under an independently accepted full domain.
/// No whitespace trimming, case folding, URL decoding or prefix-only network check.
pub fn decode(text: &str, domain: &Digest) -> Result<PaymentAddress> {
    silk_sapling_f04::address::decode(text, domain).map_err(|error| match error {
        silk_sapling_f04::Error::Encoding(reason) => Error::Invalid(reason),
        other => Error::Sapling(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sapling_crypto::zip32::ExtendedSpendingKey;

    #[test]
    fn exact_descriptor_domain_checksum_and_alias_refusals() {
        let address = ExtendedSpendingKey::master(&[37; 32]).default_address().1;
        let domain = [42; 32];
        let encoded = encode(&domain, &address);
        assert_eq!(encoded.len(), 234);
        assert_eq!(decode(&encoded, &domain).unwrap(), address);
        assert!(decode(&encoded, &[43; 32]).is_err());
        for invalid in [
            encoded.to_uppercase(),
            format!(" {encoded}"),
            format!("{encoded}\n"),
            encoded.replacen("sn3_", "sn2_", 1),
            encoded.replacen("sn3_", "zcash_", 1),
            encoded[..233].to_owned(),
        ] {
            assert!(decode(&invalid, &domain).is_err());
        }
        let mut damaged = encoded.into_bytes();
        damaged[233] = if damaged[233] == b'0' { b'1' } else { b'0' };
        assert!(decode(std::str::from_utf8(&damaged).unwrap(), &domain).is_err());
    }

    #[test]
    fn recomputed_checksum_does_not_admit_an_invalid_payment_key() {
        let mut bytes = [0; 115];
        bytes[..8].copy_from_slice(b"SNADDR03");
        bytes[8..40].copy_from_slice(&[42; 32]);
        bytes[40..83].fill(255);
        let checksum = domain_hash("SilkNode-F0-address", &[&bytes[..83]]);
        bytes[83..].copy_from_slice(&checksum);
        assert!(matches!(
            decode(&format!("sn3_{}", hex::encode(bytes)), &[42; 32]),
            Err(Error::Invalid("payment descriptor diversified key"))
        ));
    }
}
