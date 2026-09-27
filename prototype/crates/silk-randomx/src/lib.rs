#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Safe, deliberately narrow access to the pinned `RandomX` v2 implementation.
//!
//! The wrapper always uses interpreted light mode with `RANDOMX_FLAG_V2`.
//! Dataset, large-page, hardware-AES, and JIT choices are outside this API, so
//! callers cannot change consensus output through runtime optimization flags.
//! The only unsafe code is the reviewed ownership adapter in `ffi`.

#[allow(unsafe_code)]
mod ffi;

pub use ffi::{MAX_RANDOMX_INPUT_BYTES, RANDOMX_HASH_BYTES, RandomXError, RandomXV2Vm};

/// Exact pinned upstream `RandomX` release label.
pub const RANDOMX_UPSTREAM_VERSION: &str = "v2.0.1";
/// Exact pinned upstream `RandomX` commit.
pub const RANDOMX_UPSTREAM_COMMIT: &str = "aaafe71322df6602c21a5c72937ac284724ae561";
/// Original upstream `RandomX` tree before documentation-only curation.
pub const RANDOMX_UPSTREAM_TREE: &str = "57752798bc713766b34b487737b8d9258448814e";
/// Vendored tree used by the build: audit PDFs omitted and their README link redirected.
/// Native algorithm source is unchanged from the upstream commit.
pub const RANDOMX_CURATED_TREE: &str = "bee7375373c0b822a04527e954d948dc5cbb3f23";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_v2_interpreted_vector_matches() {
        let mut vm = RandomXV2Vm::new(b"test key 000").expect("initialize official v2 vector");
        let hash = vm
            .calculate_hash(b"This is a test")
            .expect("calculate official v2 vector");
        assert_eq!(
            hash,
            [
                0x22, 0xec, 0x6b, 0x86, 0x1b, 0x3e, 0xb2, 0x36, 0x86, 0xb2, 0xef, 0xba, 0xd6, 0x95,
                0x13, 0xc9, 0x67, 0xec, 0xfc, 0xe8, 0x09, 0x83, 0xdf, 0x66, 0xc9, 0xc5, 0xb4, 0xfb,
                0xfb, 0x4c, 0xdb, 0x6f,
            ]
        );
    }
}
