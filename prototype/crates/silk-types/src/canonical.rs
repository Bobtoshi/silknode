//! Canonical fixed-width encoding and bounded, fail-closed decoding.

use core::cmp::Ordering;

use thiserror::Error;

/// A structural error in a collection that is required to be sorted and unique.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CollectionError {
    /// The item at `index` is equal to its predecessor.
    #[error("duplicate item at index {index}")]
    Duplicate {
        /// Index of the second equal item.
        index: usize,
    },
    /// The item at `index` sorts before its predecessor.
    #[error("items are not in canonical order at index {index}")]
    NotSorted {
        /// Index of the first out-of-order item.
        index: usize,
    },
}

impl CollectionError {
    /// Returns a stable rejection code suitable for differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Duplicate { .. } => "canonical.duplicate_item",
            Self::NotSorted { .. } => "canonical.unsorted_items",
        }
    }
}

/// Failure while constructing canonical bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EncodeError {
    /// A platform-sized length cannot be represented by the wire `u32`.
    #[error("{kind} length {length} exceeds the canonical u32 range")]
    LengthOverflow {
        /// Name of the value being measured.
        kind: &'static str,
        /// Host-side length that did not fit.
        length: usize,
    },
    /// A set-like collection was not already in canonical order.
    #[error(transparent)]
    InvalidCollection(#[from] CollectionError),
}

impl EncodeError {
    /// Returns a stable rejection code suitable for differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LengthOverflow { .. } => "canonical.length_overflow",
            Self::InvalidCollection(error) => error.code(),
        }
    }
}

/// Failure while parsing canonical bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DecodeError {
    /// Input ended before a fixed number of bytes could be read.
    #[error(
        "unexpected end of input at offset {offset}: needed {needed} bytes, only {remaining} remain"
    )]
    UnexpectedEof {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// Number of bytes required by the read.
        needed: usize,
        /// Number of bytes still available.
        remaining: usize,
    },
    /// A top-level value decoded successfully but bytes remained.
    #[error("{remaining} trailing bytes at offset {offset}")]
    TrailingBytes {
        /// Offset immediately after the decoded value.
        offset: usize,
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// A wire `u32` length does not fit the target platform's `usize`.
    #[error("canonical length {encoded} does not fit this platform")]
    LengthDoesNotFitPlatform {
        /// Length read from the wire.
        encoded: u32,
    },
    /// A length exceeded the explicit caller-supplied consensus or resource bound.
    #[error("{kind} length {length} exceeds limit {max}")]
    LimitExceeded {
        /// Name of the bounded value.
        kind: &'static str,
        /// Decoded length.
        length: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// Memory for a bounded list could not be reserved.
    #[error("could not reserve memory for {kind} length {length}")]
    AllocationFailed {
        /// Name of the value being allocated.
        kind: &'static str,
        /// Requested element count.
        length: usize,
    },
    /// A Boolean used a byte other than canonical zero or one.
    #[error("invalid Boolean byte {value} at offset {offset}")]
    InvalidBoolean {
        /// Offset of the invalid byte.
        offset: usize,
        /// Invalid byte value.
        value: u8,
    },
    /// A tagged union or enum used a tag unknown to its active schema.
    #[error("unknown tag {value} at offset {offset}")]
    UnknownTag {
        /// Offset of the invalid tag.
        offset: usize,
        /// Unknown tag value.
        value: u8,
    },
    /// A field reserved as an all-zero derivation placeholder contained data.
    #[error("derived-field placeholder is nonzero at offset {offset}")]
    NonZeroPlaceholder {
        /// Offset of the first byte in the fixed-width placeholder.
        offset: usize,
    },
    /// A set-like collection was not in canonical order.
    #[error(transparent)]
    InvalidCollection(#[from] CollectionError),
}

impl DecodeError {
    /// Returns a stable rejection code suitable for differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnexpectedEof { .. } => "canonical.unexpected_eof",
            Self::TrailingBytes { .. } => "canonical.trailing_bytes",
            Self::LengthDoesNotFitPlatform { .. } => "canonical.length_platform_overflow",
            Self::LimitExceeded { .. } => "canonical.limit_exceeded",
            Self::AllocationFailed { .. } => "canonical.allocation_failed",
            Self::InvalidBoolean { .. } => "canonical.invalid_boolean",
            Self::UnknownTag { .. } => "canonical.unknown_tag",
            Self::NonZeroPlaceholder { .. } => "canonical.nonzero_placeholder",
            Self::InvalidCollection(error) => error.code(),
        }
    }
}

/// Validates the canonical representation of a set-like slice.
///
/// Values must be strictly increasing according to `Ord`. The reported index
/// points at the second item of the first offending adjacent pair.
///
/// # Errors
///
/// Returns [`CollectionError::Duplicate`] for an equal pair and
/// [`CollectionError::NotSorted`] for a descending pair.
pub fn validate_sorted_unique<T: Ord>(values: &[T]) -> Result<(), CollectionError> {
    for (pair_index, pair) in values.windows(2).enumerate() {
        match pair[0].cmp(&pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(CollectionError::Duplicate {
                    index: pair_index + 1,
                });
            }
            Ordering::Greater => {
                return Err(CollectionError::NotSorted {
                    index: pair_index + 1,
                });
            }
        }
    }
    Ok(())
}

/// A deterministic builder for canonical consensus bytes.
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

    /// Creates an encoder with a non-consensus capacity hint.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Returns the bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the byte count written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no bytes have been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the encoder and returns its canonical bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Writes one byte.
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Writes a little-endian `u16`.
    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a little-endian `u128`.
    pub fn write_u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a canonical Boolean (`0x00` or `0x01`).
    pub fn write_bool(&mut self, value: bool) {
        self.write_u8(u8::from(value));
    }

    /// Writes fixed-size bytes without a length prefix.
    pub fn write_fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    /// Writes a checked little-endian `u32` length.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::LengthOverflow`] if `length` does not fit the
    /// canonical wire type.
    pub fn write_len(&mut self, kind: &'static str, length: usize) -> Result<(), EncodeError> {
        let encoded =
            u32::try_from(length).map_err(|_| EncodeError::LengthOverflow { kind, length })?;
        self.write_u32(encoded);
        Ok(())
    }

    /// Writes a `u32`-length-prefixed byte string.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::LengthOverflow`] when the byte length does not
    /// fit the wire length type.
    pub fn write_bytes(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        self.write_len("byte string", value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Writes a `u32`-length-prefixed ordered list.
    ///
    /// # Errors
    ///
    /// Returns an error when the element count or an element encoding cannot
    /// be represented canonically.
    pub fn write_list<T: CanonicalEncode>(&mut self, values: &[T]) -> Result<(), EncodeError> {
        self.write_len("list", values.len())?;
        for value in values {
            value.encode(self)?;
        }
        Ok(())
    }

    /// Validates and writes a strictly sorted, unique list.
    ///
    /// # Errors
    ///
    /// Returns a collection error if the caller has not already placed values
    /// in canonical order, or a length/element encoding error.
    pub fn write_sorted_unique<T: CanonicalEncode + Ord>(
        &mut self,
        values: &[T],
    ) -> Result<(), EncodeError> {
        validate_sorted_unique(values)?;
        self.write_list(values)
    }

    /// Writes a canonical optional value using tag zero or one.
    ///
    /// # Errors
    ///
    /// Returns an error when the contained value cannot be encoded.
    pub fn write_option<T: CanonicalEncode>(
        &mut self,
        value: Option<&T>,
    ) -> Result<(), EncodeError> {
        match value {
            None => self.write_u8(0),
            Some(inner) => {
                self.write_u8(1);
                inner.encode(self)?;
            }
        }
        Ok(())
    }
}

/// A bounded parser over borrowed canonical bytes.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder positioned at the start of `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Returns the number of unconsumed bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    /// Returns whether the entire input has been consumed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.remaining() == 0
    }

    fn read_raw(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(DecodeError::UnexpectedEof {
                offset: self.offset,
                needed: length,
                remaining,
            });
        }
        let end = self.offset + length;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if no byte remains.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_raw(1)?[0])
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_fixed()?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_fixed()?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_fixed()?))
    }

    /// Reads a little-endian `u128`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than sixteen bytes remain.
    pub fn read_u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_le_bytes(self.read_fixed()?))
    }

    /// Reads a canonical Boolean.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidBoolean`] for values other than zero and
    /// one, or [`DecodeError::UnexpectedEof`] if no byte remains.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        let offset = self.offset;
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(DecodeError::InvalidBoolean { offset, value }),
        }
    }

    /// Reads an enum/union tag and checks it against an explicit allow-list.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownTag`] if the byte is not listed in
    /// `allowed`, or [`DecodeError::UnexpectedEof`] if no byte remains.
    pub fn read_tag(&mut self, allowed: &[u8]) -> Result<u8, DecodeError> {
        let offset = self.offset;
        let value = self.read_u8()?;
        if allowed.contains(&value) {
            Ok(value)
        } else {
            Err(DecodeError::UnknownTag { offset, value })
        }
    }

    /// Reads exactly `N` bytes without a length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than `N` bytes remain.
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.read_raw(N)?);
        Ok(value)
    }

    /// Reads and bounds a canonical little-endian `u32` length.
    ///
    /// # Errors
    ///
    /// Returns an error if the length prefix is truncated, does not fit the
    /// platform, or exceeds `max`.
    pub fn read_len(&mut self, kind: &'static str, max: usize) -> Result<usize, DecodeError> {
        let encoded = self.read_u32()?;
        let length = usize::try_from(encoded)
            .map_err(|_| DecodeError::LengthDoesNotFitPlatform { encoded })?;
        if length > max {
            return Err(DecodeError::LimitExceeded { kind, length, max });
        }
        Ok(length)
    }

    /// Reads a bounded `u32`-length-prefixed byte string without allocating.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated length or payload, a platform length
    /// overflow, or a length above `max_bytes`.
    pub fn read_bytes(&mut self, max_bytes: usize) -> Result<&'a [u8], DecodeError> {
        let length = self.read_len("byte string", max_bytes)?;
        self.read_raw(length)
    }

    /// Reads a bounded `u32`-length-prefixed ordered list.
    ///
    /// The bound is checked before reserving memory.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid length, failed allocation, or invalid
    /// element encoding.
    pub fn read_list<T: CanonicalDecode>(
        &mut self,
        max_items: usize,
    ) -> Result<Vec<T>, DecodeError> {
        let length = self.read_len("list", max_items)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| DecodeError::AllocationFailed {
                kind: "list",
                length,
            })?;
        for _ in 0..length {
            values.push(T::decode(self)?);
        }
        Ok(values)
    }

    /// Reads a bounded list and requires strict sorted uniqueness.
    ///
    /// # Errors
    ///
    /// Returns all errors from [`Decoder::read_list`] plus a stable collection
    /// error for duplicate or out-of-order elements.
    pub fn read_sorted_unique<T: CanonicalDecode + Ord>(
        &mut self,
        max_items: usize,
    ) -> Result<Vec<T>, DecodeError> {
        let values = self.read_list(max_items)?;
        validate_sorted_unique(&values)?;
        Ok(values)
    }

    /// Reads an optional value tagged with canonical zero or one.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownTag`] for any other tag or an element
    /// decoding error for a present value.
    pub fn read_option<T: CanonicalDecode>(&mut self) -> Result<Option<T>, DecodeError> {
        let offset = self.offset;
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(self)?)),
            value => Err(DecodeError::UnknownTag { offset, value }),
        }
    }

    /// Requires complete input consumption.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] if bytes remain.
    pub const fn finish(self) -> Result<(), DecodeError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                offset: self.offset,
                remaining,
            })
        }
    }
}

/// A value with one normative canonical byte representation.
pub trait CanonicalEncode {
    /// Appends the value to `encoder`.
    ///
    /// # Errors
    ///
    /// Returns an error when a length, collection, or nested value is not
    /// canonically representable.
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;

    /// Encodes the value into a new byte vector.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`CanonicalEncode::encode`].
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.into_bytes())
    }
}

/// A value that can be parsed from its normative canonical bytes.
pub trait CanonicalDecode: Sized {
    /// Decodes one value and leaves the decoder after it.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for malformed, non-canonical, or out-of-bounds
    /// input.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    /// Decodes one value and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a decoding error, including [`DecodeError::TrailingBytes`] when
    /// the input contains a valid prefix plus extra data.
    fn from_canonical_bytes(input: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(input)
    }
}

/// Decodes exactly one canonical value and rejects trailing bytes.
///
/// # Errors
///
/// Returns a typed decoding failure or [`DecodeError::TrailingBytes`].
pub fn decode_exact<T: CanonicalDecode>(input: &[u8]) -> Result<T, DecodeError> {
    let mut decoder = Decoder::new(input);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

macro_rules! impl_integer {
    ($type:ty, $write:ident, $read:ident) => {
        impl CanonicalEncode for $type {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
                encoder.$write(*self);
                Ok(())
            }
        }

        impl CanonicalDecode for $type {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                decoder.$read()
            }
        }
    };
}

impl_integer!(u8, write_u8, read_u8);
impl_integer!(u16, write_u16, read_u16);
impl_integer!(u32, write_u32, read_u32);
impl_integer!(u64, write_u64, read_u64);
impl_integer!(u128, write_u128, read_u128);

impl CanonicalEncode for bool {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_bool(*self);
        Ok(())
    }
}

impl CanonicalDecode for bool {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_bool()
    }
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_fixed(self);
        Ok(())
    }
}

impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_fixed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Fixture {
        version: u16,
        epoch: u64,
        enabled: bool,
        digest: [u8; 4],
    }

    impl CanonicalEncode for Fixture {
        fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
            self.version.encode(encoder)?;
            self.epoch.encode(encoder)?;
            self.enabled.encode(encoder)?;
            self.digest.encode(encoder)
        }
    }

    impl CanonicalDecode for Fixture {
        fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            Ok(Self {
                version: u16::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                enabled: bool::decode(decoder)?,
                digest: <[u8; 4]>::decode(decoder)?,
            })
        }
    }

    #[test]
    fn fixed_width_values_are_little_endian_and_round_trip() {
        let fixture = Fixture {
            version: 0x1234,
            epoch: 0x0102_0304_0506_0708,
            enabled: true,
            digest: [0xaa, 0xbb, 0xcc, 0xdd],
        };
        let bytes = fixture.to_canonical_bytes().expect("fixture encodes");
        assert_eq!(
            bytes,
            [
                0x34, 0x12, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0xaa, 0xbb, 0xcc,
                0xdd,
            ]
        );
        assert_eq!(
            Fixture::from_canonical_bytes(&bytes).expect("fixture decodes"),
            fixture
        );
    }

    #[test]
    fn byte_strings_and_lists_use_u32_length_prefixes() {
        let mut encoder = Encoder::new();
        encoder.write_bytes(b"silk").expect("short bytes encode");
        encoder
            .write_list(&[1_u16, 256_u16])
            .expect("short list encodes");
        assert_eq!(
            encoder.as_slice(),
            [4, 0, 0, 0, b's', b'i', b'l', b'k', 2, 0, 0, 0, 1, 0, 0, 1,]
        );

        let mut decoder = Decoder::new(encoder.as_slice());
        assert_eq!(decoder.read_bytes(4).expect("bytes decode"), b"silk");
        assert_eq!(decoder.read_list::<u16>(2).expect("list decodes"), [1, 256]);
        decoder.finish().expect("all bytes consumed");
    }

    #[test]
    fn exact_decode_rejects_trailing_bytes() {
        assert_eq!(
            decode_exact::<u16>(&[1, 0, 9]),
            Err(DecodeError::TrailingBytes {
                offset: 2,
                remaining: 1,
            })
        );
    }

    #[test]
    fn truncated_fixed_value_is_rejected() {
        assert_eq!(
            decode_exact::<u32>(&[1, 2, 3]),
            Err(DecodeError::UnexpectedEof {
                offset: 0,
                needed: 4,
                remaining: 3,
            })
        );
    }

    #[test]
    fn noncanonical_boolean_and_unknown_tags_are_rejected() {
        assert_eq!(
            decode_exact::<bool>(&[2]),
            Err(DecodeError::InvalidBoolean {
                offset: 0,
                value: 2,
            })
        );

        let mut decoder = Decoder::new(&[7]);
        assert_eq!(
            decoder.read_tag(&[0, 1]),
            Err(DecodeError::UnknownTag {
                offset: 0,
                value: 7,
            })
        );
    }

    #[test]
    fn lengths_are_bounded_before_payload_reads_or_allocation() {
        let prefix = 5_u32.to_le_bytes();
        let mut bytes_decoder = Decoder::new(&prefix);
        assert_eq!(
            bytes_decoder.read_bytes(4),
            Err(DecodeError::LimitExceeded {
                kind: "byte string",
                length: 5,
                max: 4,
            })
        );

        let mut list_decoder = Decoder::new(&prefix);
        assert_eq!(
            list_decoder.read_list::<u8>(4),
            Err(DecodeError::LimitExceeded {
                kind: "list",
                length: 5,
                max: 4,
            })
        );
    }

    #[test]
    fn truncated_length_prefixed_payload_is_rejected() {
        let input = [4, 0, 0, 0, 1, 2, 3];
        let mut decoder = Decoder::new(&input);
        assert_eq!(
            decoder.read_bytes(4),
            Err(DecodeError::UnexpectedEof {
                offset: 4,
                needed: 4,
                remaining: 3,
            })
        );
    }

    #[test]
    fn sorted_unique_validation_rejects_duplicates_and_reordering() {
        assert_eq!(
            validate_sorted_unique(&[1, 1, 2]),
            Err(CollectionError::Duplicate { index: 1 })
        );
        assert_eq!(
            validate_sorted_unique(&[1, 3, 2]),
            Err(CollectionError::NotSorted { index: 2 })
        );

        let mut encoder = Encoder::new();
        assert_eq!(
            encoder.write_sorted_unique(&[1_u8, 1]),
            Err(EncodeError::InvalidCollection(CollectionError::Duplicate {
                index: 1
            }))
        );
        assert!(encoder.is_empty());
    }

    #[test]
    fn sorted_unique_decoder_rejects_noncanonical_wire_order() {
        let input = [3, 0, 0, 0, 1, 3, 2];
        let mut decoder = Decoder::new(&input);
        assert_eq!(
            decoder.read_sorted_unique::<u8>(3),
            Err(DecodeError::InvalidCollection(CollectionError::NotSorted {
                index: 2
            }))
        );
    }

    #[test]
    fn option_uses_only_zero_and_one_tags() {
        let mut encoder = Encoder::new();
        encoder
            .write_option(Some(&0x1234_u16))
            .expect("option encodes");
        encoder.write_option::<u16>(None).expect("none encodes");
        assert_eq!(encoder.as_slice(), [1, 0x34, 0x12, 0]);

        let mut decoder = Decoder::new(encoder.as_slice());
        assert_eq!(
            decoder.read_option::<u16>().expect("some decodes"),
            Some(0x1234)
        );
        assert_eq!(decoder.read_option::<u16>().expect("none decodes"), None);
        decoder.finish().expect("all bytes consumed");

        let mut invalid = Decoder::new(&[2]);
        assert_eq!(
            invalid.read_option::<u16>(),
            Err(DecodeError::UnknownTag {
                offset: 0,
                value: 2,
            })
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn encoder_rejects_lengths_above_wire_range_without_allocating() {
        let length = usize::try_from(u64::from(u32::MAX) + 1).expect("64-bit usize");
        let mut encoder = Encoder::new();
        assert_eq!(
            encoder.write_len("fixture", length),
            Err(EncodeError::LengthOverflow {
                kind: "fixture",
                length,
            })
        );
        assert!(encoder.is_empty());
    }

    #[test]
    fn errors_expose_stable_codes() {
        assert_eq!(
            DecodeError::UnknownTag {
                offset: 0,
                value: 9,
            }
            .code(),
            "canonical.unknown_tag"
        );
        assert_eq!(
            CollectionError::Duplicate { index: 1 }.code(),
            "canonical.duplicate_item"
        );
        assert_eq!(
            DecodeError::NonZeroPlaceholder { offset: 4 }.code(),
            "canonical.nonzero_placeholder"
        );
    }
}
