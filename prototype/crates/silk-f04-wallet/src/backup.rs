//! Exact bounded encrypted KEY backup. No wallet balance, cursor or pending-state
//! authority is serialized here. No plaintext secret ever goes to a file.
use crate::{Error, Result, WalletKey};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, RenameFlags, openat, renameat_with};
use sapling_crypto::zip32::ExtendedSpendingKey;
use silk_sapling_f04::Digest;
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use zeroize::Zeroizing;

const HEADER: usize = 104;
const PAYLOAD: usize = 8 + 169;
/// One exact local envelope size; never a peer-controlled allocation/KDF bound.
pub const BACKUP_BYTES: usize = HEADER + PAYLOAD + 16;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
// Logical Argon2 lanes; this implementation creates no worker threads.
const LANES: u32 = 4;

pub(crate) fn password_ok(password: &str) -> bool {
    password.len() <= 1024 && password.chars().count() >= 15
}
pub(crate) fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params =
        Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).map_err(|_| Error::Authentication)?;
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| Error::Unavailable("KDF memory"))?;
    blocks.resize(params.block_count(), Block::default());
    let mut blocks = Zeroizing::new(blocks);
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            password.as_bytes(),
            salt,
            key.as_mut(),
            blocks.as_mut_slice(),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}
fn header(domain: Digest, salt: &[u8; 16], nonce: &[u8; 24]) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..8].copy_from_slice(b"SNF04BK1");
    // Version1 fixes Argon2id0x13 + XChaCha20-Poly1305, not negotiable algorithms.
    h[8..12].copy_from_slice(&[1, 0, 0, 0]);
    h[12..44].copy_from_slice(&domain);
    h[44..48].copy_from_slice(&MEMORY_KIB.to_le_bytes());
    h[48..52].copy_from_slice(&ITERATIONS.to_le_bytes());
    h[52..56].copy_from_slice(&LANES.to_le_bytes());
    h[56..60].copy_from_slice(&[1, 0, 0, 0]);
    h[60..76].copy_from_slice(salt);
    h[76..100].copy_from_slice(nonce);
    h[100..104].copy_from_slice(
        &u32::try_from(PAYLOAD + 16)
            .expect("fixed backup length")
            .to_le_bytes(),
    );
    h
}
/// Encrypt one existing local research key with fresh OS salt/nonce. Password
/// callers must use protected interactive/descriptor input, never argv/env/logs.
/// # Errors
/// Refuses weak passwords, unavailable entropy/memory or encryption failure.
pub fn seal(key: &WalletKey, password: &str) -> Result<Vec<u8>> {
    if !password_ok(password) {
        return Err(Error::PasswordPolicy);
    }
    let mut salt = [0; 16];
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut salt)
        .and_then(|()| OsRng.try_fill_bytes(&mut nonce))
        .map_err(|_| Error::Unavailable("backup entropy"))?;
    let aad = header(key.domain, &salt, &nonce);
    let encryption_key = derive(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_ref())
        .map_err(|_| Error::Authentication)?;
    let serialized = Zeroizing::new(key.key.to_bytes());
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD + 16));
    payload.extend_from_slice(b"SNF04SK1");
    payload.extend_from_slice(serialized.as_ref());
    cipher
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut *payload)
        .map_err(|_| Error::Authentication)?;
    let mut out = Vec::with_capacity(BACKUP_BYTES);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&payload);
    Ok(out)
}
/// Check exact context/framing before any KDF allocation, authenticate the AEAD,
/// then parse the standard exact169-byte XSK. This restores signing authority,
/// NOT spendability.
/// # Errors
/// Refuses noncanonical framing, wrong context/password, corruption or unavailable memory.
pub fn open(bytes: &[u8], expected_domain: Digest, password: &str) -> Result<WalletKey> {
    if bytes.len() != BACKUP_BYTES || !password_ok(password) {
        return Err(Error::Authentication);
    }
    let salt: [u8; 16] = bytes[60..76]
        .try_into()
        .map_err(|_| Error::Authentication)?;
    let nonce: [u8; 24] = bytes[76..100]
        .try_into()
        .map_err(|_| Error::Authentication)?;
    if bytes[..HEADER] != header(expected_domain, &salt, &nonce) {
        return Err(Error::Authentication);
    }
    let encryption_key = derive(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_ref())
        .map_err(|_| Error::Authentication)?;
    let mut payload = Zeroizing::new(bytes[HEADER..].to_vec());
    cipher
        .decrypt_in_place(&XNonce::from(nonce), &bytes[..HEADER], &mut *payload)
        .map_err(|_| Error::Authentication)?;
    if payload.len() != PAYLOAD || &payload[..8] != b"SNF04SK1" {
        return Err(Error::Authentication);
    }
    let key = ExtendedSpendingKey::from_bytes(&payload[8..]).map_err(|_| Error::Authentication)?;
    let encoded = Zeroizing::new(key.to_bytes());
    if encoded.as_ref() != &payload[8..] {
        return Err(Error::Authentication);
    }
    Ok(WalletKey {
        domain: expected_domain,
        key,
        first_use: false,
    })
}

fn parent(path: &Path) -> Result<(File, &OsStr)> {
    let name = path
        .file_name()
        .ok_or(Error::Unavailable("backup filename"))?;
    let path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let m = dir.metadata()?;
    if m.mode() & 0o777 != 0o700 || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Unavailable(
            "backup parent must be owned private0700",
        ));
    }
    Ok((dir, name))
}
/// Atomically publish a newly encrypted key backup without replacing ANY path.
///
/// The caller must reserve this small write on its separately qualified capped
/// wallet volume. Partial encrypted stages remain on failure; never auto-delete.
/// An error after rename is publication-uncertain: the complete destination may
/// exist. Inspect/reopen it explicitly; never overwrite it as an automatic retry.
/// # Errors
/// Returns authentication, path, entropy or I/O errors; publication may be uncertain.
pub fn save_new(path: &Path, key: &WalletKey, password: &str) -> Result<()> {
    let (dir, name) = parent(path)?;
    match rustix::fs::statat(&dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Err(Error::Unavailable("backup destination already exists")),
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(std::io::Error::from(e).into()),
    }
    let bytes = seal(key, password)?;
    let mut id = [0; 16];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|_| Error::Unavailable("backup stage entropy"))?;
    let stage = format!("f04-backup-stage-{}", hex::encode(id));
    let mut file: File = openat(
        &dir,
        stage.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?
    .into();
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != dir.metadata()?.uid()
        || metadata.nlink() != 1
    {
        return Err(Error::Unavailable("backup stage identity/mode"));
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    renameat_with(&dir, stage.as_str(), &dir, name, RenameFlags::NOREPLACE)
        .map_err(std::io::Error::from)?;
    dir.sync_all()?;
    Ok(())
}
/// Read exact bounded ciphertext through a pinned private parent descriptor.
/// Refuse symlinks, hard links, unexpected ownership/modes, FIFOs and trailing data.
/// # Errors
/// Returns path/I/O errors or uniform backup authentication refusal.
pub fn load(path: &Path, domain: Digest, password: &str) -> Result<WalletKey> {
    let (dir, name) = parent(path)?;
    let file: File = openat(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let m = file.metadata()?;
    if !m.is_file()
        || m.len() != BACKUP_BYTES as u64
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.uid() != dir.metadata()?.uid()
    {
        return Err(Error::Unavailable("backup file type/ownership/mode/length"));
    }
    let mut bytes = Vec::with_capacity(BACKUP_BYTES + 1);
    file.take(BACKUP_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    open(&bytes, domain, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FreshKey;
    const PASSWORD: &str = "PUBLIC TEST PASSWORD ONLY";
    #[test]
    fn real_backup_restores_only_key_and_refuses_wrong_context_password_or_bytes() {
        let key = FreshKey::generate().unwrap().bind([17; 32]);
        let bytes = seal(&key, PASSWORD).unwrap();
        assert_eq!(bytes.len(), BACKUP_BYTES);
        let restored = open(&bytes, key.domain(), PASSWORD).unwrap();
        assert_eq!(
            restored.address_candidate([0; 11]).unwrap().address,
            key.address_candidate([0; 11]).unwrap().address
        );
        assert!(matches!(
            open(&bytes, key.domain(), "WRONG PUBLIC TEST PASSWORD"),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            open(&bytes, [18; 32], PASSWORD),
            Err(Error::Authentication)
        ));
        let mut altered = bytes.clone();
        altered[44] ^= 1;
        assert!(matches!(
            open(&altered, key.domain(), PASSWORD),
            Err(Error::Authentication)
        ));
        let mut altered = bytes.clone();
        altered[BACKUP_BYTES - 1] ^= 1;
        assert!(matches!(
            open(&altered, key.domain(), PASSWORD),
            Err(Error::Authentication)
        ));
        let mut altered = bytes;
        altered.push(0);
        assert!(matches!(
            open(&altered, key.domain(), PASSWORD),
            Err(Error::Authentication)
        ));
        assert!(matches!(seal(&key, "short"), Err(Error::PasswordPolicy)));
    }
    #[test]
    fn private_no_clobber_file_restore_and_path_refusals() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = FreshKey::generate().unwrap().bind([23; 32]);
        let path = dir.path().join("key.backup");
        save_new(&path, &key, PASSWORD).unwrap();
        let before = std::fs::read(&path).unwrap();
        let restored = load(&path, key.domain(), PASSWORD).unwrap();
        assert_eq!(
            restored.address_candidate([0; 11]).unwrap().address,
            key.address_candidate([0; 11]).unwrap().address
        );
        assert!(save_new(&path, &key, PASSWORD).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(load(&alias, key.domain(), PASSWORD).is_err());
        let linked = dir.path().join("hard-link");
        std::fs::hard_link(&path, &linked).unwrap();
        assert!(load(&path, key.domain(), PASSWORD).is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}
