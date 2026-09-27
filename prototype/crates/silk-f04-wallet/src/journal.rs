//! Encrypted local address-allocation journal, not ledger or balance authority.
//!
//! An independently retained head pin is required on reopen. Old valid ciphertext
//! does not prove freshness. Every stage/orphan remains retained on failure.
use crate::{AddressCandidate, Error, Result, WalletKey, backup};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use rand_core::{OsRng, RngCore};
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags};
use silk_sapling_f04::{Digest, codec::domain_hash};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use zeroize::Zeroizing;

pub mod intents;

const STORE_BYTES: usize = 72;
const RECORD_HEADER: usize = 104;
const PAYLOAD_BYTES: usize = 64;
const RECORD_BYTES: usize = RECORD_HEADER + PAYLOAD_BYTES + 16;
const RESERVATION: u64 = 64 * 1024;
const MARGIN: u64 = 4 * 1024 * 1024 * 1024;
const PAUSE: u64 = 14 * 1024 * 1024 * 1024;
/// Finite local journal horizon; no pruning or cursor reset at exhaustion.
pub const MAX_RECORDS: u64 = 65_536;
const MAX_FILES: u64 = 4 * MAX_RECORDS + 8;

/// Mutation receipt. Retain `head` independently before relying on later reopen.
/// Losing that receipt is a continuity problem, not permission to adopt a HEAD.
pub struct IssuedAddress {
    /// Public diversified address whose cursor was durably advanced first.
    pub address: AddressCandidate,
    /// Exact new local continuity pin; no public-ledger authority.
    pub head: Digest,
}

/// Single-writer local journal. It does not expose or persist signing keys,
/// balances, canonical confirmations or a claim that recovery is complete.
pub struct Journal<'a> {
    key: &'a WalletKey,
    directory: File,
    _lock: File,
    margin: File,
    header: [u8; STORE_BYTES],
    cipher_key: Zeroizing<[u8; 32]>,
    head: Digest,
    sequence: u64,
    next: Option<[u8; 11]>,
    used: Inventory,
    poisoned: bool,
    faults: Faults,
}

// Deterministic local I/O-boundary tests; production has no armed fault field or
// external injection control. Not a substitute for power-loss/runtime testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    Created,
    Written,
    Synced,
    Renamed,
    Durable,
}
#[derive(Default)]
struct Faults {
    #[cfg(test)]
    at: Option<(bool, Boundary)>,
}
impl Faults {
    #[cfg(test)]
    fn check(&self, is_head: bool, boundary: Boundary) -> Result<()> {
        if self.at == Some((is_head, boundary)) {
            return Err(std::io::Error::other("injected journal publication boundary").into());
        }
        Ok(())
    }
    #[cfg(not(test))]
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "Match the per-handle fallible test hook without production injection state"
    )]
    fn check(&self, _is_head: bool, _boundary: Boundary) -> Result<()> {
        Ok(())
    }
}

fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Unavailable("journal entropy"))?;
    Ok(bytes)
}
fn identity(file: &File, directory: &File, exact: Option<u64>) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != directory.metadata()?.uid()
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o600
        || exact.is_some_and(|n| m.len() != n)
    {
        return Err(Error::Unavailable("journal file identity/mode/length"));
    }
    Ok(())
}
fn open_dir(path: &Path, private: bool) -> Result<File> {
    let directory: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    if private {
        let m = directory.metadata()?;
        if m.mode() & 0o777 != 0o700 || m.uid() != rustix::process::geteuid().as_raw() {
            return Err(Error::Unavailable(
                "journal requires owned private0700 directory",
            ));
        }
    }
    Ok(directory)
}
fn read(dir: &File, name: &str, exact: usize) -> Result<Vec<u8>> {
    let file: File = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    identity(&file, dir, Some(exact as u64))?;
    let mut bytes = Vec::with_capacity(exact + 1);
    file.take(exact as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != exact {
        return Err(Error::Unavailable("journal changed read"));
    }
    Ok(bytes)
}
fn fresh_file(dir: &File, name: &str) -> Result<File> {
    let file: File = rustix::fs::openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?
    .into();
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
    identity(&file, dir, Some(0))?;
    Ok(file)
}
fn publish(dir: &File, name: &str, bytes: &[u8], replace: bool, faults: &Faults) -> Result<()> {
    let stage = format!("stage-{}", hex::encode(entropy::<16>()?));
    let mut file = fresh_file(dir, &stage)?;
    let is_head = matches!(name, "HEAD" | "INTENT_HEAD");
    faults.check(is_head, Boundary::Created)?;
    file.write_all(bytes)?;
    faults.check(is_head, Boundary::Written)?;
    file.sync_all()?;
    faults.check(is_head, Boundary::Synced)?;
    if replace {
        rustix::fs::renameat(dir, stage.as_str(), dir, name).map_err(std::io::Error::from)?;
    } else {
        rustix::fs::renameat_with(dir, stage.as_str(), dir, name, RenameFlags::NOREPLACE)
            .map_err(std::io::Error::from)?;
    }
    faults.check(is_head, Boundary::Renamed)?;
    dir.sync_all()?;
    faults.check(is_head, Boundary::Durable)?;
    Ok(())
}
fn binding(key: &WalletKey) -> Zeroizing<Digest> {
    let encoded = Zeroizing::new(key.key.to_bytes());
    Zeroizing::new(domain_hash(
        "SilkNode-F04-local-wallet-key",
        &[&key.domain, encoded.as_ref()],
    ))
}
fn record_id(bytes: &[u8]) -> Digest {
    domain_hash("SilkNode-F04-local-wallet-record", &[bytes])
}
fn record_name(id: Digest) -> String {
    format!("record-{}", hex::encode(id))
}
#[derive(Clone, Copy)]
struct Inventory {
    bytes: u64,
    files: u64,
}
impl Inventory {
    fn reserve(&self) -> Result<()> {
        if self.files.checked_add(2).is_none_or(|n| n > MAX_FILES) {
            return Err(Error::Unavailable("journal entry reservation"));
        }
        Ok(())
    }
}
fn inventory(directory: &File) -> Result<Inventory> {
    let mut used = 4096_u64;
    let mut count = 0_u64;
    for entry in rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        count += 1;
        if count > MAX_FILES {
            return Err(Error::Unavailable("journal inventory horizon"));
        }
        let file: File = rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?
        .into();
        identity(&file, directory, None)?;
        let metadata = file.metadata()?;
        let rounded = metadata
            .len()
            .checked_add(4095)
            .map(|n| n / 4096 * 4096)
            .ok_or(Error::Unavailable("journal inventory overflow"))?;
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or(Error::Unavailable("journal allocation overflow"))?;
        used = used
            .checked_add(rounded.max(allocated))
            .and_then(|n| n.checked_add(4096))
            .ok_or(Error::Unavailable("journal inventory overflow"))?;
        if used > PAUSE {
            return Err(Error::Unavailable("journal retained byte horizon"));
        }
    }
    Ok(Inventory {
        bytes: used,
        files: count,
    })
}
fn fits(host_free: u128, wallet_free: u128, used: u128, extra: u64, same: bool) -> bool {
    host_free >= u128::from(MARGIN) + if same { u128::from(extra) } else { 0 }
        && wallet_free >= u128::from(extra)
        && used + u128::from(extra) <= u128::from(PAUSE)
}
fn capacity(directory: &File, margin: &File, accounted: u64, extra: u64) -> Result<()> {
    let wallet = rustix::fs::fstatvfs(directory).map_err(std::io::Error::from)?;
    let host = rustix::fs::fstatvfs(margin).map_err(std::io::Error::from)?;
    let free = |v: &rustix::fs::StatVfs| u128::from(v.f_bavail) * u128::from(v.f_frsize);
    // Same-filesystem component tests do not claim a hard16GiB volume. The
    // qualified runtime uses a separate capped volume and includes ALL its use.
    let same = directory.metadata()?.dev() == margin.metadata()?.dev();
    let used = if same {
        u128::from(accounted)
    } else {
        (u128::from(wallet.f_blocks.saturating_sub(wallet.f_bavail)) * u128::from(wallet.f_frsize))
            .max(u128::from(accounted))
    };
    if !fits(free(&host), free(&wallet), used, extra, same) {
        return Err(Error::Unavailable("journal storage reservation/margin"));
    }
    Ok(())
}

impl<'a> Journal<'a> {
    /// Create once for a freshly generated bound research key, never a restored
    /// key. Consume that permission BEFORE any attempted mutation. The default
    /// address may already be in genesis, so always begin AFTER its index.
    /// Caller must qualify the capped volume and separately retain the first pin.
    /// # Errors
    /// Refuses nonfresh keys, password policy, unsafe paths, resource or I/O failure.
    /// A failed creation after first-use consumption cannot be automatically retried.
    pub fn create(
        path: &Path,
        margin: &Path,
        key: &'a mut WalletKey,
        password: &str,
    ) -> Result<Self> {
        if !key.first_use {
            return Err(Error::Unavailable("key has no fresh journal provenance"));
        }
        if !backup::password_ok(password) {
            return Err(Error::PasswordPolicy);
        }
        key.first_use = false;
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_dir(parent_path, true)?;
        let name = path
            .file_name()
            .ok_or(Error::Unavailable("journal directory name"))?;
        let margin = open_dir(margin, false)?;
        capacity(&parent, &margin, 0, RESERVATION)?;
        rustix::fs::mkdirat(&parent, name, Mode::RWXU).map_err(std::io::Error::from)?;
        let directory: File = rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?
        .into();
        rustix::fs::fchmod(&directory, Mode::RWXU).map_err(std::io::Error::from)?;
        parent.sync_all()?;
        let lock = fresh_file(&directory, "LOCK")?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        lock.sync_all()?;
        let mut header = [0; STORE_BYTES];
        header[..8].copy_from_slice(b"SNF04WJ1");
        header[8..40].copy_from_slice(&key.domain);
        header[40..56].copy_from_slice(&entropy::<16>()?);
        header[56..].copy_from_slice(&entropy::<16>()?);
        let cipher_key = backup::derive(password, &header[56..])?;
        publish(&directory, "STORE", &header, false, &Faults::default())?;
        let next = key.address_candidate([0; 11])?.next;
        let mut journal = Self {
            key,
            directory,
            _lock: lock,
            margin,
            header,
            cipher_key,
            head: [0; 32],
            sequence: 0,
            next,
            used: Inventory {
                bytes: 4 * 4096,
                files: 2,
            },
            poisoned: false,
            faults: Faults::default(),
        };
        journal.write_state(0, next, true)?;
        Ok(journal)
    }
    /// Open only the exact independently retained head. No missing-state reset,
    /// orphan promotion, previous-head fallback or directory-derived freshness.
    /// # Errors
    /// Refuses stale pins, wrong keys/passwords, malformed files, missing state,
    /// another writer, unsafe paths or unavailable storage.
    pub fn open(
        path: &Path,
        margin: &Path,
        key: &'a WalletKey,
        password: &str,
        expected: Digest,
    ) -> Result<Self> {
        if !backup::password_ok(password) {
            return Err(Error::Authentication);
        }
        let directory = open_dir(path, true)?;
        let lock: File = rustix::fs::openat(
            &directory,
            "LOCK",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?
        .into();
        identity(&lock, &directory, Some(0))?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        if read(&directory, "HEAD", 32)? != expected {
            return Err(Error::Unavailable("wallet continuity pin mismatch"));
        }
        let header: [u8; STORE_BYTES] = read(&directory, "STORE", STORE_BYTES)?
            .try_into()
            .map_err(|_| Error::Authentication)?;
        if &header[..8] != b"SNF04WJ1" || header[8..40] != key.domain {
            return Err(Error::Authentication);
        }
        let cipher_key = backup::derive(password, &header[56..])?;
        let bytes = read(&directory, &record_name(expected), RECORD_BYTES)?;
        if record_id(&bytes) != expected {
            return Err(Error::Authentication);
        }
        if &bytes[..8] != b"SNF04WA1"
            || bytes[8..40] != domain_hash("SilkNode-F04-local-wallet-store", &[&header])
        {
            return Err(Error::Authentication);
        }
        let sequence = u64::from_le_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| Error::Authentication)?,
        );
        if sequence >= MAX_RECORDS || (sequence == 0) != (bytes[48..80] == [0; 32]) {
            return Err(Error::Authentication);
        }
        let nonce: [u8; 24] = bytes[80..104]
            .try_into()
            .map_err(|_| Error::Authentication)?;
        let mut payload = Zeroizing::new(bytes[RECORD_HEADER..].to_vec());
        XChaCha20Poly1305::new_from_slice(cipher_key.as_ref())
            .map_err(|_| Error::Authentication)?
            .decrypt_in_place(&XNonce::from(nonce), &bytes[..RECORD_HEADER], &mut *payload)
            .map_err(|_| Error::Authentication)?;
        if payload.len() != PAYLOAD_BYTES
            || &payload[..8] != b"SNF04AC1"
            || payload[8..40] != *binding(key)
            || payload[40] > 1
            || payload[52..] != [0; 12]
            || (payload[40] == 0 && payload[41..52] != [0; 11])
        {
            return Err(Error::Authentication);
        }
        let next = if payload[40] == 1 {
            Some(
                payload[41..52]
                    .try_into()
                    .map_err(|_| Error::Authentication)?,
            )
        } else {
            None
        };
        let margin = open_dir(margin, false)?;
        let used = inventory(&directory)?;
        capacity(&directory, &margin, used.bytes, 0)?;
        Ok(Self {
            key,
            directory,
            _lock: lock,
            margin,
            header,
            cipher_key,
            head: expected,
            sequence,
            next,
            used,
            poisoned: false,
            faults: Faults::default(),
        })
    }
    /// Local pin only; not anti-rollback beyond the independently retained receipt.
    /// # Errors
    /// Refuses an uncertain/poisoned publication handle.
    pub const fn head(&self) -> Result<Digest> {
        if self.poisoned {
            return Err(Error::Unavailable("wallet publication uncertain"));
        }
        Ok(self.head)
    }
    /// Allocate exactly the next valid diversified address. Never return it before
    /// the new encrypted state AND head are durable. Any write error poisons this
    /// handle, including errors after a head may already have been published.
    /// # Errors
    /// Refuses exhaustion, stale continuity, storage limits or publication failure.
    pub fn issue_address(&mut self) -> Result<IssuedAddress> {
        self.head()?;
        let start = self
            .next
            .ok_or(Error::Unavailable("address space exhausted"))?;
        let candidate = self.key.address_candidate(start)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n < MAX_RECORDS)
            .ok_or(Error::Unavailable("wallet journal horizon"))?;
        self.write_state(sequence, candidate.next, false)?;
        Ok(IssuedAddress {
            address: candidate,
            head: self.head,
        })
    }
    fn write_state(&mut self, sequence: u64, next: Option<[u8; 11]>, initial: bool) -> Result<()> {
        self.head()?;
        self.used.reserve()?;
        capacity(&self.directory, &self.margin, self.used.bytes, RESERVATION)?;
        if !initial {
            self.poisoned = true;
            if read(&self.directory, "HEAD", 32)? != self.head {
                return Err(Error::Unavailable("wallet continuity changed"));
            }
            self.poisoned = false;
        }
        let nonce = entropy::<24>()?;
        let mut header = [0; RECORD_HEADER];
        header[..8].copy_from_slice(b"SNF04WA1");
        header[8..40].copy_from_slice(&domain_hash(
            "SilkNode-F04-local-wallet-store",
            &[&self.header],
        ));
        header[40..48].copy_from_slice(&sequence.to_le_bytes());
        header[48..80].copy_from_slice(&self.head);
        header[80..].copy_from_slice(&nonce);
        let mut payload = Zeroizing::new(vec![0; PAYLOAD_BYTES]);
        payload[..8].copy_from_slice(b"SNF04AC1");
        payload[8..40].copy_from_slice(binding(self.key).as_ref());
        if let Some(cursor) = next {
            payload[40] = 1;
            payload[41..52].copy_from_slice(&cursor);
        }
        XChaCha20Poly1305::new_from_slice(self.cipher_key.as_ref())
            .map_err(|_| Error::Authentication)?
            .encrypt_in_place(&XNonce::from(nonce), &header, &mut *payload)
            .map_err(|_| Error::Authentication)?;
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&payload);
        let head = record_id(&bytes);
        self.used.bytes += RESERVATION;
        self.used.files += 2;
        self.poisoned = true;
        publish(
            &self.directory,
            &record_name(head),
            &bytes,
            false,
            &self.faults,
        )?;
        publish(&self.directory, "HEAD", &head, !initial, &self.faults)?;
        // Inventory every retained stage/object after publication. Do not demand
        // another write reservation before returning this completed mutation.
        self.used = inventory(&self.directory)?;
        capacity(&self.directory, &self.margin, self.used.bytes, 0)?;
        self.head = head;
        self.sequence = sequence;
        self.next = next;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FreshKey;
    const PASSWORD: &str = "PUBLIC JOURNAL TEST PASSWORD";
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn addresses_are_committed_before_return_and_resume_only_at_exact_pin() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let fresh = FreshKey::generate().unwrap();
        let initial = fresh.initial_address();
        let mut key = fresh.bind([21; 32]);
        let encrypted_backup = backup::seal(&key, PASSWORD).unwrap();
        let mut journal = Journal::create(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let old = journal.head().unwrap();
        let first = journal.issue_address().unwrap();
        assert_ne!(first.address.address, initial);
        let second = journal.issue_address().unwrap();
        assert_ne!(first.address.address, second.address.address);
        let pin = second.head;
        drop(journal);
        assert!(Journal::open(&path, dir.path(), &key, PASSWORD, old).is_err());
        assert!(Journal::open(&path, dir.path(), &key, "WRONG PUBLIC PASSWORD", pin).is_err());
        let mut restored = backup::open(&encrypted_backup, key.domain(), PASSWORD).unwrap();
        assert!(
            Journal::create(
                &dir.path().join("reset"),
                dir.path(),
                &mut restored,
                PASSWORD
            )
            .is_err()
        );
        assert!(!dir.path().join("reset").exists());
        let mut reopened = Journal::open(&path, dir.path(), &restored, PASSWORD, pin).unwrap();
        assert!(Journal::open(&path, dir.path(), &key, PASSWORD, pin).is_err());
        let third = reopened.issue_address().unwrap();
        assert_ne!(third.address.address, second.address.address);
        assert_ne!(third.address.address, first.address.address);
    }
    #[test]
    fn changed_head_or_missing_lock_never_resets_or_promotes_an_orphan() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([22; 32]);
        let mut journal = Journal::create(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let original = journal.head().unwrap();
        std::fs::write(path.join("HEAD"), [7; 32]).unwrap();
        assert!(journal.issue_address().is_err());
        assert!(journal.head().is_err());
        assert!(journal.issue_address().is_err());
        drop(journal);
        assert!(Journal::open(&path, dir.path(), &key, PASSWORD, original).is_err());
        std::fs::rename(path.join("LOCK"), path.join("retained-lock")).unwrap();
        assert!(Journal::open(&path, dir.path(), &key, PASSWORD, [7; 32]).is_err());
        assert!(!path.join("LOCK").exists());
        assert!(
            Journal::create(&dir.path().join("second"), dir.path(), &mut key, PASSWORD).is_err()
        );
    }

    #[test]
    fn publication_boundaries_withhold_output_and_retain_accounted_evidence() {
        for is_head in [false, true] {
            for boundary in [
                Boundary::Created,
                Boundary::Written,
                Boundary::Synced,
                Boundary::Renamed,
                Boundary::Durable,
            ] {
                let dir = private_dir();
                let path = dir.path().join("wallet");
                let mut key = FreshKey::generate().unwrap().bind([23; 32]);
                let mut journal = Journal::create(&path, dir.path(), &mut key, PASSWORD).unwrap();
                let old = journal.head().unwrap();
                let before = inventory(&journal.directory).unwrap().bytes;
                journal.faults.at = Some((is_head, boundary));
                assert!(journal.issue_address().is_err());
                assert!(journal.head().is_err());
                assert!(journal.issue_address().is_err());
                assert!(inventory(&journal.directory).unwrap().bytes > before);
                let current = read(&journal.directory, "HEAD", 32).unwrap();
                drop(journal);
                let reopened = Journal::open(&path, dir.path(), &key, PASSWORD, old);
                if current == old {
                    let reopened = reopened.unwrap();
                    assert!(reopened.used.bytes > before);
                    assert_eq!(reopened.head().unwrap(), old);
                } else {
                    assert!(is_head && matches!(boundary, Boundary::Renamed | Boundary::Durable));
                    assert!(reopened.is_err());
                }
            }
        }
    }
    #[test]
    fn capacity_postcondition_does_not_reserve_a_second_write() {
        assert!(
            Inventory {
                bytes: 0,
                files: MAX_FILES - 2
            }
            .reserve()
            .is_ok()
        );
        assert!(
            Inventory {
                bytes: 0,
                files: MAX_FILES - 1
            }
            .reserve()
            .is_err()
        );
        assert!(
            Inventory {
                bytes: 0,
                files: MAX_FILES
            }
            .reserve()
            .is_err()
        );
        let before = PAUSE - RESERVATION;
        assert!(fits(
            u128::from(MARGIN),
            1_000_000,
            u128::from(before),
            RESERVATION,
            false
        ));
        let after = before + 12_288;
        assert!(fits(
            u128::from(MARGIN),
            1_000_000,
            u128::from(after),
            0,
            false
        ));
        assert!(!fits(
            u128::from(MARGIN),
            1_000_000,
            u128::from(after),
            RESERVATION,
            false
        ));
        assert!(!fits(
            u128::from(MARGIN),
            u128::from(MARGIN),
            0,
            RESERVATION,
            true
        ));
        assert!(fits(
            u128::from(MARGIN + RESERVATION),
            u128::from(MARGIN + RESERVATION),
            0,
            RESERVATION,
            true
        ));
    }
}
