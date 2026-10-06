//! Durable R2 scope consumption preparation, not accepted-profile or release authority.
//! One `(profile, round)` can be consumed once, regardless of manifest/message.
//! No secret, proof, ciphertext or recoverable worker state is serialized.
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

/// Local owned-store failure; no peer-visible diagnostic or proof rejection.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// Continuity, framing or lifecycle unavailable.
    #[error("AIP2 scope unavailable: {0}")]
    Unavailable(&'static str),
    /// Local storage uncertainty consumes the attempted scope and stops this owner.
    #[error("AIP2 scope I/O: {0}")]
    Io(#[from] std::io::Error),
}
/// Fallible local ownership operation.
pub type ClaimResult<T> = std::result::Result<T, ClaimError>;

/// Separately selected local store role; never a relay-received role field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClaimRole {
    Client = 1,
    Exit = 2,
}

/// Structurally bound preparation inputs. These are NOT an accepted/co-signed P.
/// No conversion to a profile, worker or release capability is provided here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreparedClaimBinding {
    /// Local client or exit owner, not a peer claim.
    pub role: ClaimRole,
    /// Exact local ledger domain.
    pub domain: [u8; 32],
    /// Exact local configuration hash.
    pub config: [u8; 32],
    /// P identifier selected by the future accepted-profile owner.
    pub profile: [u8; 32],
    /// Full standalone VK hash; structural binding does not approve provenance.
    pub vk_hash: [u8; 32],
    /// Fixed 2880-round profile epoch.
    pub epoch: u32,
}

/// Same external rollback-domain obligation as the existing relay PinRetention.
/// Implementers must durably retain this latest pin before returning success.
/// The component cannot prove independent custody or hardware anti-rollback.
pub trait ClaimPinRetention {
    /// Persist outside the scope snapshot's rollback domain or return uncertainty.
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()>;
}

// Type erasure changes no consume/reopen semantics or custody requirement.
#[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
impl<T: ClaimPinRetention + ?Sized> ClaimPinRetention for Box<T> {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        (**self).retain_claim_pin(pin)
    }
}

const BYTES: usize = 512;
const OLD_VK: [u8; 32] = [
    0x25, 0x5e, 0x1f, 0x10, 0xdd, 0x2c, 0x02, 0x5c, 0xe1, 0x61, 0x8c, 0x0a, 0x3c, 0xb3, 0x23, 0x39,
    0xdd, 0x83, 0xf5, 0xc0, 0xd4, 0xff, 0xc4, 0xd2, 0xcb, 0xe6, 0xd5, 0xf7, 0x62, 0xb3, 0xbd, 0x61,
];

/// Fixed-size snapshot, exclusive owned-directory lock and exact external pin.
/// Any uncertain mutation poisons this object. Reopen never yields old permits.
pub struct PreparedScopeStore<P: ClaimPinRetention> {
    directory: File,
    _lock: File,
    bytes: [u8; BYTES],
    pin: [u8; 32],
    binding: PreparedClaimBinding,
    floor: u64,
    pins: P,
    failed: bool,
}

/// Borrowed one-shot local consumption receipt. No Clone/Deserialize/constructor,
/// proof/job/ciphertext recovery or conversion to release authorization exists.
/// Its mutable borrow also prevents a second claim while this receipt is held.
pub struct ConsumedScope<'a, P: ClaimPinRetention> {
    _owner: &'a mut PreparedScopeStore<P>,
    round: u64,
    manifest: [u8; 32],
    message: [u8; 32],
}
impl<P: ClaimPinRetention> ConsumedScope<'_, P> {
    pub(crate) fn binding(&self) -> PreparedClaimBinding {
        self._owner.binding
    }
    /// The original common-scope round, never a retry round.
    pub const fn round(&self) -> u64 {
        self.round
    }
    /// Immutable manifest consistency record.
    pub const fn manifest(&self) -> [u8; 32] {
        self.manifest
    }
    /// Immutable selected message digest, never cached proof/ciphertext bytes.
    pub const fn message(&self) -> [u8; 32] {
        self.message
    }
}

impl<P: ClaimPinRetention> PreparedScopeStore<P> {
    /// Create only in a new empty owned0700 directory. This selects no profile
    /// or runtime. Publication and external pin retention finish before return.
    pub fn create(path: &Path, binding: PreparedClaimBinding, pins: P) -> ClaimResult<Self> {
        let first = bounds(binding)?;
        let directory = open_directory(path)?;
        inventory(&directory, false)?;
        let lock = fresh(&directory, "LOCK")?;
        lock.sync_all()?;
        lock_exclusive(&lock)?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"SNAICL02");
        bytes[8] = binding.role as u8;
        bytes[16..48].copy_from_slice(&binding.domain);
        bytes[48..80].copy_from_slice(&binding.config);
        bytes[80..112].copy_from_slice(&binding.profile);
        bytes[112..144].copy_from_slice(&binding.vk_hash);
        bytes[144..148].copy_from_slice(&binding.epoch.to_le_bytes());
        let mut store = Self {
            directory,
            _lock: lock,
            bytes,
            pin: [0; 32],
            binding,
            floor: first,
            pins,
            failed: true,
        };
        store.publish(bytes, false)?;
        Ok(store)
    }
    /// Reopen only with an independently retained latest pin and trusted local
    /// restart round. Skip interrupted/current rounds; never adopt stored pins
    /// or resume a prior worker. A numeric argument alone is not clock evidence.
    pub fn open(
        path: &Path,
        binding: PreparedClaimBinding,
        expected_pin: [u8; 32],
        trusted_restart_round: u64,
        pins: P,
    ) -> ClaimResult<Self> {
        let first = bounds(binding)?;
        let directory = open_directory(path)?;
        inventory(&directory, true)?;
        let lock = existing(&directory, "LOCK", 0)?;
        lock_exclusive(&lock)?;
        let mut current = existing(&directory, "CURRENT", BYTES as u64)?;
        let mut bytes = [0; BYTES];
        current.read_exact(&mut bytes)?;
        check_bytes(&bytes, binding)?;
        let pin = digest(&bytes);
        if pin != expected_pin || expected_pin == [0; 32] {
            return Err(ClaimError::Unavailable("latest independently retained pin"));
        }
        let next = if bytes[9] == 1 {
            round(&bytes).checked_add(1)
        } else {
            Some(first)
        }
        .ok_or(ClaimError::Unavailable("high-water overflow"))?;
        let floor = first.max(next).max(
            trusted_restart_round
                .checked_add(3)
                .ok_or(ClaimError::Unavailable("restart floor overflow"))?,
        );
        let mut store = Self {
            directory,
            _lock: lock,
            bytes,
            pin,
            binding,
            floor,
            pins,
            failed: true,
        };
        store.pins.retain_claim_pin(pin)?;
        store.failed = false;
        Ok(store)
    }
    /// Only public snapshot evidence. This getter is not retained-pin custody.
    pub const fn pin(&self) -> [u8; 32] {
        self.pin
    }
    /// Fresh-round high-water/floor, not permission to activate a profile.
    pub const fn earliest_round(&self) -> u64 {
        self.floor
    }
    /// Atomically consume the common profile/round BEFORE worker handoff or any
    /// proof/ciphertext escape. A failed job/drop never rolls this state back.
    /// Manifest/message are consistency data, not extra keys permitting reproof.
    pub fn consume(
        &mut self,
        selected_round: u64,
        manifest: [u8; 32],
        message: [u8; 32],
    ) -> ClaimResult<ConsumedScope<'_, P>> {
        if self.failed {
            return Err(ClaimError::Unavailable("poisoned scope owner"));
        }
        let first = bounds(self.binding)?;
        if selected_round < self.floor
            || selected_round < first
            || selected_round >= first + 2880
            || manifest == [0; 32]
            || (self.bytes[9] == 1 && selected_round <= round(&self.bytes))
        {
            return Err(ClaimError::Unavailable("consumed or foreign scope"));
        }
        self.failed = true;
        inventory(&self.directory, true)?;
        let mut current = existing(&self.directory, "CURRENT", BYTES as u64)?;
        let mut actual = [0; BYTES];
        current.read_exact(&mut actual)?;
        if actual != self.bytes || digest(&actual) != self.pin {
            return Err(ClaimError::Unavailable("live scope bytes changed"));
        }
        let mut next = self.bytes;
        next[9] = 1;
        next[152..160].copy_from_slice(&selected_round.to_le_bytes());
        next[160..192].copy_from_slice(&manifest);
        next[192..224].copy_from_slice(&message);
        next[224..256].copy_from_slice(&self.pin);
        self.publish(next, true)?;
        self.floor = selected_round + 1;
        Ok(ConsumedScope {
            _owner: self,
            round: selected_round,
            manifest,
            message,
        })
    }
    fn publish(&mut self, next: [u8; BYTES], replace: bool) -> ClaimResult<()> {
        self.failed = true;
        #[cfg(test)]
        if replace {
            crash_checkpoint("before_stage");
        }
        let free = rustix::fs::fstatvfs(&self.directory).map_err(std::io::Error::from)?;
        if !free
            .f_bavail
            .checked_mul(free.f_frsize)
            .is_some_and(|n| n >= 64 * 1024)
        {
            return Err(ClaimError::Unavailable("scope-store reserve"));
        }
        let mut stage = fresh(&self.directory, "STAGE")?;
        stage.write_all(&next)?;
        #[cfg(test)]
        if replace {
            crash_checkpoint("snapshot_written");
        }
        stage.sync_all()?;
        #[cfg(test)]
        if replace {
            crash_checkpoint("snapshot_fsynced");
        }
        if replace {
            rustix::fs::renameat(&self.directory, "STAGE", &self.directory, "CURRENT")
                .map_err(std::io::Error::from)?;
        } else {
            rustix::fs::renameat_with(
                &self.directory,
                "STAGE",
                &self.directory,
                "CURRENT",
                RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
        }
        #[cfg(test)]
        if replace {
            crash_checkpoint("snapshot_renamed");
        }
        self.directory.sync_all()?;
        #[cfg(test)]
        if replace {
            crash_checkpoint("directory_fsynced");
        }
        self.bytes = next;
        self.pin = digest(&next);
        self.pins.retain_claim_pin(self.pin)?;
        #[cfg(test)]
        if replace {
            crash_checkpoint("pin_retained");
        }
        self.failed = false;
        Ok(())
    }
}

// Native child-only fault boundary. Absent from every non-test build.
#[cfg(test)]
pub(crate) fn crash_checkpoint(label: &str) {
    if std::env::var("SILKNODE_SCOPE_CRASH_POINT").ok().as_deref() == Some(label) {
        println!("SCOPE_CHECKPOINT {label}");
        let _ = std::io::stdout().flush();
        loop {
            std::thread::park();
        }
    }
}
fn bounds(binding: PreparedClaimBinding) -> ClaimResult<u64> {
    if [
        binding.domain,
        binding.config,
        binding.profile,
        binding.vk_hash,
    ]
    .contains(&[0; 32])
        || binding.vk_hash == OLD_VK
    {
        return Err(ClaimError::Unavailable(
            "zero or historical profile/VK binding",
        ));
    }
    Ok(u64::from(binding.epoch) * 2880)
}
fn round(bytes: &[u8; BYTES]) -> u64 {
    u64::from_le_bytes(bytes[152..160].try_into().expect("eight"))
}
fn digest(bytes: &[u8; BYTES]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn check_bytes(bytes: &[u8; BYTES], binding: PreparedClaimBinding) -> ClaimResult<()> {
    let first = bounds(binding)?;
    if &bytes[..8] != b"SNAICL02"
        || bytes[8] != binding.role as u8
        || bytes[9] > 1
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != binding.domain
        || bytes[48..80] != binding.config
        || bytes[80..112] != binding.profile
        || bytes[112..144] != binding.vk_hash
        || bytes[144..148] != binding.epoch.to_le_bytes()
        || bytes[148..152] != [0; 4]
        || bytes[256..].iter().any(|b| *b != 0)
        || (bytes[9] == 0 && bytes[152..256].iter().any(|b| *b != 0))
        || (bytes[9] == 1
            && (round(bytes) < first
                || round(bytes) >= first + 2880
                || bytes[160..192] == [0; 32]
                || bytes[224..256] == [0; 32]))
    {
        return Err(ClaimError::Unavailable("scope snapshot framing/context"));
    }
    Ok(())
}
fn open_directory(path: &Path) -> ClaimResult<File> {
    let file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let m = file.metadata()?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o777 != 0o700 {
        return Err(ClaimError::Unavailable("owned0700 scope directory"));
    }
    Ok(file)
}
fn identity(file: &File, directory: &File, length: u64) -> ClaimResult<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != directory.metadata()?.uid()
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o600
        || m.len() != length
    {
        return Err(ClaimError::Unavailable("owned0600 single-link scope file"));
    }
    Ok(())
}
fn fresh(directory: &File, name: &str) -> ClaimResult<File> {
    let file: File = rustix::fs::openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?
    .into();
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
    identity(&file, directory, 0)?;
    Ok(file)
}
fn existing(directory: &File, name: &str, length: u64) -> ClaimResult<File> {
    let file: File = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    identity(&file, directory, length)?;
    Ok(file)
}
fn lock_exclusive(file: &File) -> ClaimResult<()> {
    rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)?;
    Ok(())
}
fn inventory(directory: &File, initialized: bool) -> ClaimResult<()> {
    let mut mask = 0;
    for entry in rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        match entry.file_name().to_bytes() {
            b"." | b".." => (),
            b"CURRENT" if initialized => mask |= 1,
            b"LOCK" if initialized => mask |= 2,
            _ => return Err(ClaimError::Unavailable("scope residue/inventory")),
        }
    }
    if initialized && mask != 3 {
        return Err(ClaimError::Unavailable("scope files missing"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
