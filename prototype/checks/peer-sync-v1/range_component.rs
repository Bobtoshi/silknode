//! Third-party-style checks use the public compiled library, not private source.
#[cfg(test)]
mod sync {
    use silk_f04_node::{
        carriage::MAX_VERTEX_BYTES,
        sync::{RANGE_LIMIT_V1, RangeBatchV1},
    };

    fn frame(values: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(values.len()).unwrap()];
        for value in values {
            bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    #[test]
    fn public_adapter_preserves_unverified_bytes_and_existing_limits() {
        let bytes = frame(&[b"unverified", b"still not a valid carrier"]);
        let range = RangeBatchV1::decode(&bytes, 4094, 4096).unwrap();
        assert_eq!(
            range.carriers(),
            &[
                b"unverified".as_slice(),
                b"still not a valid carrier".as_slice()
            ]
        );
        let maximum = vec![7; MAX_VERTEX_BYTES];
        let bytes = frame(&vec![maximum.as_slice(); RANGE_LIMIT_V1]);
        assert_eq!(
            RangeBatchV1::decode(&bytes, 4064, 4096)
                .unwrap()
                .carriers()
                .len(),
            32
        );
    }

    #[test]
    fn public_adapter_refuses_incomplete_excessive_or_trailing_frames() {
        let good = frame(&[b"first", b"second"]);
        for cut in 0..good.len() {
            assert!(RangeBatchV1::decode(&good[..cut], 0, 2).is_err());
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(RangeBatchV1::decode(&extra, 0, 2).is_err());
        for (bytes, start, total) in [
            (&[0][..], 0, 1),
            (&[33][..], 0, 4096),
            (good.as_slice(), 0, 1),
            (good.as_slice(), usize::MAX, 4096),
            (good.as_slice(), 0, 4097),
            (good.as_slice(), 2, 2),
        ] {
            assert!(RangeBatchV1::decode(bytes, start, total).is_err());
        }
        assert!(RangeBatchV1::decode(&frame(&[b""]), 0, 1).is_err());
        let mut oversized = vec![1];
        oversized.extend_from_slice(&u32::try_from(MAX_VERTEX_BYTES + 1).unwrap().to_be_bytes());
        assert!(RangeBatchV1::decode(&oversized, 0, 1).is_err());
    }
}
