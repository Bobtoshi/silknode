//! Authenticate entire canonical Sapling ceremony files before parsing parameters.

use crate::{Error, Result};
use sapling_crypto::circuit::{
    OutputParameters, PreparedOutputVerifyingKey, PreparedSpendVerifyingKey, SpendParameters,
};
use std::{fs::File, io::Read, path::Path};

/// Canonical spend-file length including ceremony suffix.
pub const SPEND_BYTES: usize = 47_958_396;
/// Canonical output-file length including ceremony suffix.
pub const OUTPUT_BYTES: usize = 3_592_860;
/// F0.4's BLAKE2b-512 identity of the complete spend file.
pub const SPEND_BLAKE2B: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
/// F0.4's BLAKE2b-512 identity of the complete output file.
pub const OUTPUT_BLAKE2B: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

/// Only exact profile parameters can construct this capability.
pub struct SaplingParameters {
    pub(crate) spend: SpendParameters,
    pub(crate) output: OutputParameters,
    pub(crate) spend_vk: PreparedSpendVerifyingKey,
    pub(crate) output_vk: PreparedOutputVerifyingKey,
}

/// Authenticated verification-only capability. Cannot produce a Sapling proof.
/// Unlike proving parameters, retains no large Groth16 query arrays.
pub struct SaplingVerificationKeys {
    pub(crate) spend_vk: PreparedSpendVerifyingKey,
    pub(crate) output_vk: PreparedOutputVerifyingKey,
}
impl SaplingVerificationKeys {
    /// Stream each WHOLE canonical ceremony file once, retaining only its VK
    /// prefix from that same authenticated stream. Never seek/reopen after hashing.
    /// No curve parser runs before the whole-file length and `BLAKE2b` match.
    /// # Errors
    /// Refuses file/type/length/hash/encoding mismatch or unsupported file admission.
    pub fn load(spend_path: &Path, output_path: &Path) -> Result<Self> {
        let spend = authenticated_vk(spend_path, SPEND_BYTES, SPEND_BLAKE2B, 8)?;
        let output = authenticated_vk(output_path, OUTPUT_BYTES, OUTPUT_BLAKE2B, 6)?;
        // Sapling0.7 keeps VK wrapper constructors private. Its public parameter
        // parser accepts the exact authenticated VK followed by five empty query
        // arrays. These temporary wrappers are NEVER exposed as proving params;
        // only their actual VK precomputations survive. No proof input/key changes.
        let mut spend_reader = std::io::Cursor::new(spend.as_slice());
        let spend_vk = SpendParameters::read(&mut spend_reader, true)?.prepared_verifying_key();
        let mut output_reader = std::io::Cursor::new(output.as_slice());
        let output_vk = OutputParameters::read(&mut output_reader, true)?.prepared_verifying_key();
        if spend_reader.position() != spend.len() as u64
            || output_reader.position() != output.len() as u64
        {
            return Err(Error::Parameters("verification-key adapter consumption"));
        }
        Ok(Self {
            spend_vk,
            output_vk,
        })
    }
}

fn authenticated_vk(path: &Path, expected: usize, digest: &str, inputs: usize) -> Result<Vec<u8>> {
    let mut file = open_regular(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() != expected as u64 {
        return Err(Error::Parameters("file length/type"));
    }
    // Bellman0.14:3 uncompressed G1 +3 G2 +BE u32 IC count +IC G1s.
    let prefix_len = 868 + 96 * inputs;
    let mut prefix = Vec::with_capacity(prefix_len + 20);
    let mut chunk = vec![0; 64 * 1024];
    let mut hash = blake2b_simd::State::new();
    let mut total = 0;
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        total += read;
        if total > expected {
            return Err(Error::Parameters("whole-file length/BLAKE2b-512"));
        }
        let retain = read.min(prefix_len - prefix.len());
        prefix.extend_from_slice(&chunk[..retain]);
        hash.update(&chunk[..read]);
    }
    if total != expected || hash.finalize().to_hex().as_str() != digest {
        return Err(Error::Parameters("whole-file length/BLAKE2b-512"));
    }
    if prefix.len() != prefix_len
        || u32::from_be_bytes(
            prefix[864..868]
                .try_into()
                .map_err(|_| Error::Parameters("VK length"))?,
        ) as usize
            != inputs
    {
        return Err(Error::Parameters("canonical VK public input count"));
    }
    prefix.resize(prefix_len + 20, 0);
    Ok(prefix)
}

impl SaplingParameters {
    /// Read bounded files once; verify their whole-file identity before any curve parser.
    /// The same in-memory authenticated bytes are parsed, avoiding reopen/TOCTOU substitution.
    ///
    /// # Errors
    /// Returns `Io` for open/read/parse failures, `Parameters` for identity/type/size
    /// mismatches, or `Resource` on unsupported file-admission platforms.
    pub fn load(spend_path: &Path, output_path: &Path) -> Result<Self> {
        let spend_bytes = authenticated_file(spend_path, SPEND_BYTES, SPEND_BLAKE2B)?;
        let spend = SpendParameters::read(&spend_bytes[..], false)?;
        drop(spend_bytes);
        let output_bytes = authenticated_file(output_path, OUTPUT_BYTES, OUTPUT_BLAKE2B)?;
        let output = OutputParameters::read(&output_bytes[..], false)?;
        let spend_vk = spend.prepared_verifying_key();
        let output_vk = output.prepared_verifying_key();
        Ok(Self {
            spend,
            output,
            spend_vk,
            output_vk,
        })
    }
}

fn authenticated_file(path: &Path, expected: usize, digest: &str) -> Result<Vec<u8>> {
    let file = open_regular(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() != expected as u64 {
        return Err(Error::Parameters("file length/type"));
    }
    let mut bytes = Vec::with_capacity(expected + 1);
    file.take(expected as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != expected || blake2b_simd::blake2b(&bytes).to_hex().as_str() != digest {
        return Err(Error::Parameters("whole-file length/BLAKE2b-512"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // Refuse symlinks and do not block while opening a FIFO/device. The same opened
    // descriptor is then checked as a regular file before allocating or reading.
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_regular(_path: &Path) -> Result<File> {
    Err(Error::Resource(
        "parameter file admission unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_short_wrong_digest_and_directory_without_parameter_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-parameters");
        std::fs::write(&path, [1, 2, 3]).unwrap();
        assert!(matches!(
            authenticated_file(&path, SPEND_BYTES, SPEND_BLAKE2B),
            Err(Error::Parameters(_))
        ));
        assert!(matches!(
            authenticated_file(&path, 3, SPEND_BLAKE2B),
            Err(Error::Parameters(_))
        ));
        assert!(matches!(
            authenticated_file(dir.path(), 3, SPEND_BLAKE2B),
            Err(Error::Parameters(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuse_parameter_symlink_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        let alias = dir.path().join("alias");
        std::fs::write(&path, [1, 2, 3]).unwrap();
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(matches!(
            authenticated_file(&alias, 3, SPEND_BLAKE2B),
            Err(Error::Io(_))
        ));
    }
}
