//! Versioned, bounded public range framing. Decoding grants NO node validity.
//! Third-party transports must submit every returned carrier to `Node::ingest`.
use crate::{Error, Result, carriage::MAX_VERTEX_BYTES};

/// Existing full-range transport batch bound, not a new consensus parameter.
pub const RANGE_LIMIT_V1: usize = 32;
/// Existing F0.4 reference graph horizon; this adapter does not lift it.
pub const HISTORY_LIMIT_V1: usize = 4096;

/// Complete syntactically framed batch of UNVERIFIED full carriers.
/// No public constructor can create `VerifiedVertex` or receiver authority.
#[derive(Debug)]
pub struct RangeBatchV1<'a> {
    carriers: Vec<&'a [u8]>,
}
impl<'a> RangeBatchV1<'a> {
    /// Decode the existing count/BE-length range response before any ingestion.
    /// The peer's horizon is only a resource bound, never state/work authority.
    pub fn decode(bytes: &'a [u8], start: usize, advertised_total: usize) -> Result<Self> {
        if advertised_total > HISTORY_LIMIT_V1 || start >= advertised_total {
            return Err(Error::Invalid("sync range horizon"));
        }
        let count = usize::from(*bytes.first().ok_or(Error::Invalid("sync range count"))?);
        if count == 0 || count > RANGE_LIMIT_V1 || count > advertised_total - start {
            return Err(Error::Invalid("sync range count/bounds"));
        }
        let mut carriers = Vec::with_capacity(count);
        let mut at = 1_usize;
        for _ in 0..count {
            let end = at
                .checked_add(4)
                .ok_or(Error::Invalid("sync offset overflow"))?;
            let length = bytes
                .get(at..end)
                .ok_or(Error::Invalid("sync range length"))?;
            let size = usize::try_from(u32::from_be_bytes(
                length
                    .try_into()
                    .map_err(|_| Error::Invalid("sync range length"))?,
            ))
            .map_err(|_| Error::Invalid("sync carrier size"))?;
            if size == 0 || size > MAX_VERTEX_BYTES {
                return Err(Error::Invalid("sync carrier size"));
            }
            at = end;
            let end = at
                .checked_add(size)
                .ok_or(Error::Invalid("sync offset overflow"))?;
            carriers.push(
                bytes
                    .get(at..end)
                    .ok_or(Error::Invalid("sync range truncated"))?,
            );
            at = end;
        }
        if at != bytes.len() {
            return Err(Error::Invalid("sync range trailing bytes"));
        }
        Ok(Self { carriers })
    }

    /// Borrow complete unverified bytes in this source's advertised order.
    #[must_use]
    pub fn carriers(&self) -> &[&'a [u8]] {
        &self.carriers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(values: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(values.len()).unwrap()];
        for value in values {
            bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    #[test]
    fn complete_bounded_ranges_preserve_bytes_without_claiming_validity() {
        let bytes = batch(&[b"not a valid carrier", b"another unverified carrier"]);
        let decoded = RangeBatchV1::decode(&bytes, 4094, 4096).unwrap();
        assert_eq!(
            decoded.carriers(),
            &[
                b"not a valid carrier".as_slice(),
                b"another unverified carrier".as_slice()
            ]
        );
        let maximum = vec![7; MAX_VERTEX_BYTES];
        let bytes = batch(&[&maximum]);
        assert_eq!(
            RangeBatchV1::decode(&bytes, 0, 1).unwrap().carriers()[0],
            maximum
        );
        let bytes = batch(&vec![maximum.as_slice(); RANGE_LIMIT_V1]);
        assert_eq!(
            RangeBatchV1::decode(&bytes, 4064, 4096)
                .unwrap()
                .carriers()
                .len(),
            RANGE_LIMIT_V1
        );
    }

    #[test]
    fn malformed_or_excessive_ranges_refuse_as_a_whole() {
        let good = batch(&[b"first", b"second"]);
        for cut in 0..good.len() {
            assert!(RangeBatchV1::decode(&good[..cut], 0, 2).is_err());
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(RangeBatchV1::decode(&trailing, 0, 2).is_err());
        assert!(RangeBatchV1::decode(&[0], 0, 1).is_err());
        assert!(RangeBatchV1::decode(&[33], 0, 4096).is_err());
        assert!(RangeBatchV1::decode(&good, 0, 1).is_err());
        assert!(RangeBatchV1::decode(&good, usize::MAX, 4096).is_err());
        assert!(RangeBatchV1::decode(&good, 0, 4097).is_err());
        assert!(RangeBatchV1::decode(&batch(&[b""]), 0, 1).is_err());
        let mut oversized = vec![1];
        oversized.extend_from_slice(&u32::try_from(MAX_VERTEX_BYTES + 1).unwrap().to_be_bytes());
        assert!(RangeBatchV1::decode(&oversized, 0, 1).is_err());
    }
}
