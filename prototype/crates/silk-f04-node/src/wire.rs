//! Checked fixed-width helpers; never serialize Rust layouts into consensus bytes.
use crate::{Digest, Error, Result};
use sha2::{Digest as _, Sha256};

pub(crate) fn raw_hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

pub(crate) fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Invalid("offset overflow"))?)
        .ok_or(Error::Invalid("truncated field"))?
        .try_into()
        .map_err(|_| Error::Invalid("field length"))
}

pub(crate) fn u64le(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(bytes, at)?))
}
pub(crate) fn u32le(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, at)?))
}

pub(crate) fn prefixed_message(label: &'static str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(label.len() + 1 + body.len());
    m.push(u8::try_from(label.len()).expect("fixed label"));
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(body);
    m
}
