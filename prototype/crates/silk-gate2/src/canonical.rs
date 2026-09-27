//! Minimal bounded canonical codec and framed hashing support.

use sha2::{Digest, Sha256};

use crate::Error;

/// Canonical encoder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends one byte.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a little-endian integer.
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a little-endian integer.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a little-endian integer.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a little-endian integer.
    pub fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends fixed bytes.
    pub fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// Appends a canonical Boolean.
    pub fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    /// Appends a canonical list count.
    pub fn count(&mut self, value: usize) -> Result<(), Error> {
        let value = u32::try_from(value).map_err(|_| Error::code("canonical.length_overflow"))?;
        self.u32(value);
        Ok(())
    }

    /// Borrows encoded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Encodes one nested byte-cap subject atomically and rejects an oversized
/// canonical representation before appending any of it to its parent.
pub(crate) fn encode_with_byte_cap(
    parent: &mut Encoder,
    byte_cap: usize,
    encode: impl FnOnce(&mut Encoder) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut nested = Encoder::new();
    encode(&mut nested)?;
    let bytes = nested.finish();
    if bytes.len() > byte_cap {
        return Err(Error::code("canonical.byte_limit_exceeded"));
    }
    parent.fixed(&bytes);
    Ok(())
}

/// A canonically encodable value.
pub trait CanonicalEncode {
    /// Appends the exact encoding to `encoder`.
    fn encode(&self, encoder: &mut Encoder) -> Result<(), Error>;

    /// Returns the exact canonical bytes.
    fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.finish())
    }
}

/// A bounded canonical decoder.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    limit: usize,
    limit_is_byte_cap: bool,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over an exact byte slice.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            limit: bytes.len(),
            limit_is_byte_cap: false,
        }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.limit - self.offset
    }

    /// Current offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Reads fixed bytes.
    pub fn fixed(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| Error::code("canonical.length_overflow"))?;
        if end > self.limit {
            return Err(Error::code(if self.limit_is_byte_cap {
                "canonical.byte_limit_exceeded"
            } else {
                "canonical.unexpected_eof"
            }));
        }
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Error::code("canonical.unexpected_eof"))?;
        self.offset = end;
        Ok(value)
    }

    /// Decodes one nested byte-cap subject without allowing it to read beyond
    /// its exact cap. An enclosing cap retains precedence over a nested cap.
    pub(crate) fn within_byte_cap<T>(
        &mut self,
        byte_cap: usize,
        decode: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let old_limit = self.limit;
        let old_limit_is_byte_cap = self.limit_is_byte_cap;
        if let Some(nested_limit) = self.offset.checked_add(byte_cap)
            && nested_limit < self.limit
        {
            self.limit = nested_limit;
            self.limit_is_byte_cap = true;
        }
        let result = decode(self);
        self.limit = old_limit;
        self.limit_is_byte_cap = old_limit_is_byte_cap;
        result
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed(1)?[0])
    }

    /// Reads a little-endian integer.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.fixed(2)?.try_into().expect("fixed"),
        ))
    }

    /// Reads a little-endian integer.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.fixed(4)?.try_into().expect("fixed"),
        ))
    }

    /// Reads a little-endian integer.
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.fixed(8)?.try_into().expect("fixed"),
        ))
    }

    /// Reads a little-endian integer.
    pub fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_le_bytes(
            self.fixed(16)?.try_into().expect("fixed"),
        ))
    }

    /// Reads an exact canonical Boolean.
    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::code("canonical.invalid_boolean")),
        }
    }

    /// Reads an exact canonical option tag.
    pub fn option_tag(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::code("canonical.invalid_option")),
        }
    }

    /// Reads a count, checking input sufficiency before its semantic cap.
    pub fn count(
        &mut self,
        semantic_max: usize,
        minimum_item_bytes: usize,
    ) -> Result<usize, Error> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| Error::code("canonical.length_overflow"))?;
        if minimum_item_bytes != 0 && count > self.remaining() / minimum_item_bytes {
            return Err(Error::code("canonical.unexpected_eof"));
        }
        if count > semantic_max {
            return Err(Error::code("canonical.limit_exceeded"));
        }
        Ok(count)
    }

    /// Requires a known tag.
    pub fn tag(&mut self, allowed: &[u8]) -> Result<u8, Error> {
        let value = self.u8()?;
        if allowed.contains(&value) {
            Ok(value)
        } else {
            Err(Error::code("canonical.unknown_tag"))
        }
    }

    /// Requires a known semantic version.
    pub fn version(&mut self, expected: u8) -> Result<(), Error> {
        if self.u8()? == expected {
            Ok(())
        } else {
            Err(Error::code("canonical.unknown_version"))
        }
    }

    /// Requires complete consumption.
    pub fn finish(self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::code("canonical.trailing_bytes"))
        }
    }
}

/// A canonically decodable value.
pub trait CanonicalDecode: Sized {
    /// Decodes one value, leaving trailing-byte policy to the caller.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error>;

    /// Decodes one exact value and rejects trailing bytes.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let value = Self::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }
}

/// A decoded wire value that has no semantic authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unverified<T>(T);

impl<T> Unverified<T> {
    /// Borrows the decoded value for validation and exact comparison.
    #[must_use]
    pub const fn decoded(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper inside a trusted promotion implementation.
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

/// Canonical top-level wire type.
pub trait TopLevelWire: CanonicalEncode + Sized {
    /// Closed top-level tag.
    const TAG: u8;
    /// Frozen semantic version.
    const VERSION: u8;
    /// Stricter complete-type byte cap, or the generic cap.
    const BYTE_CAP: usize = crate::MAX_TOP_LEVEL_BYTES;

    /// Decodes fields after the validated two-byte prefix.
    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, Error>;
}

/// Enforces the generic top-level cap before the selected type-specific cap.
pub(crate) fn enforce_top_level_byte_cap<T: TopLevelWire>(length: usize) -> Result<(), Error> {
    if length > crate::MAX_TOP_LEVEL_BYTES || length > T::BYTE_CAP {
        return Err(Error::code("canonical.byte_limit_exceeded"));
    }
    Ok(())
}

/// Decodes a complete top-level object into a non-authoritative wrapper.
pub fn decode_unverified<T: TopLevelWire>(bytes: &[u8]) -> Result<Unverified<T>, Error> {
    enforce_top_level_byte_cap::<T>(bytes.len())?;
    let mut decoder = Decoder::new(bytes);
    if decoder.u8()? != T::TAG {
        return Err(Error::code("canonical.unknown_tag"));
    }
    decoder.version(T::VERSION)?;
    let value = T::decode_fields(&mut decoder)?;
    decoder.finish()?;
    Ok(Unverified(value))
}

/// Computes the predecessor-compatible framed SHA-256 transcript.
pub(crate) fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    if domain.is_empty() {
        return Err(Error::code("hash.empty_domain"));
    }
    let domain_len =
        u32::try_from(domain.len()).map_err(|_| Error::code("hash.length_overflow"))?;
    let part_count = u32::try_from(parts.len()).map_err(|_| Error::code("hash.length_overflow"))?;
    let mut digest = Sha256::new();
    digest.update(b"SilkNode-Domain-Hash-v1\0");
    digest.update(domain_len.to_le_bytes());
    digest.update(domain);
    digest.update(part_count.to_le_bytes());
    for part in parts {
        let len = u32::try_from(part.len()).map_err(|_| Error::code("hash.length_overflow"))?;
        digest.update(len.to_le_bytes());
        digest.update(part);
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Gate2ProfileV1, MAX_INTERVAL_BYTES, MAX_TOP_LEVEL_BYTES, OrderedIntervalV1};

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TinyTopLevel;

    impl CanonicalEncode for TinyTopLevel {
        fn encode(&self, encoder: &mut Encoder) -> Result<(), Error> {
            encoder.u8(Self::TAG);
            encoder.u8(Self::VERSION);
            Ok(())
        }
    }

    impl TopLevelWire for TinyTopLevel {
        const TAG: u8 = 0x7e;
        const VERSION: u8 = 1;
        const BYTE_CAP: usize = 2;

        fn decode_fields(_decoder: &mut Decoder<'_>) -> Result<Self, Error> {
            Ok(Self)
        }
    }

    #[test]
    fn exact_numeric_top_level_caps_are_enforced_without_allocation() {
        assert!(enforce_top_level_byte_cap::<OrderedIntervalV1>(MAX_INTERVAL_BYTES).is_ok());
        assert_eq!(
            enforce_top_level_byte_cap::<OrderedIntervalV1>(MAX_INTERVAL_BYTES + 1)
                .unwrap_err()
                .as_code(),
            "canonical.byte_limit_exceeded",
        );
        assert!(enforce_top_level_byte_cap::<Gate2ProfileV1>(MAX_TOP_LEVEL_BYTES).is_ok());
        assert_eq!(
            enforce_top_level_byte_cap::<Gate2ProfileV1>(MAX_TOP_LEVEL_BYTES + 1)
                .unwrap_err()
                .as_code(),
            "canonical.byte_limit_exceeded",
        );
    }

    #[test]
    fn selected_type_byte_cap_precedes_wrong_tag() {
        assert_eq!(
            decode_unverified::<TinyTopLevel>(&[0xff, TinyTopLevel::VERSION, 0])
                .unwrap_err()
                .as_code(),
            "canonical.byte_limit_exceeded",
        );
        assert_eq!(
            decode_unverified::<TinyTopLevel>(&[0xff, TinyTopLevel::VERSION])
                .unwrap_err()
                .as_code(),
            "canonical.unknown_tag",
        );
    }

    #[test]
    fn nested_cap_distinguishes_cap_from_physical_eof_and_restores_parent() {
        let bytes = [1, 2, 3, 4, 5];
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(
            decoder
                .within_byte_cap(2, |nested| nested.fixed(3).map(|_| ()))
                .unwrap_err()
                .as_code(),
            "canonical.byte_limit_exceeded",
        );
        assert_eq!(decoder.offset(), 0);
        assert_eq!(decoder.fixed(1).unwrap(), &[1]);
        assert_eq!(
            decoder
                .within_byte_cap(8, |nested| nested.fixed(5).map(|_| ()))
                .unwrap_err()
                .as_code(),
            "canonical.unexpected_eof",
        );

        let mut decoder = Decoder::new(&bytes);
        assert_eq!(
            decoder
                .within_byte_cap(1, |nested| nested.fixed(1).map(|value| value[0]))
                .unwrap(),
            1,
        );
        assert_eq!(decoder.u8().unwrap(), 2);
    }

    #[test]
    fn nested_encoding_is_atomic_at_its_exact_cap() {
        let mut parent = Encoder::new();
        encode_with_byte_cap(&mut parent, 2, |nested| {
            nested.fixed(&[1, 2]);
            Ok(())
        })
        .unwrap();
        assert_eq!(parent.bytes(), &[1, 2]);

        let before = parent.bytes().to_vec();
        assert_eq!(
            encode_with_byte_cap(&mut parent, 2, |nested| {
                nested.fixed(&[3, 4, 5]);
                Ok(())
            })
            .unwrap_err()
            .as_code(),
            "canonical.byte_limit_exceeded",
        );
        assert_eq!(parent.bytes(), before);
    }
}
