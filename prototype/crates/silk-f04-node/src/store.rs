//! Task-owned, append-only content store and atomic single-head publication.
//! Unreachable files are retained/accounted, never promoted or garbage-collected.
use crate::{Digest, Error, Result, wire::raw_hash};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_OBJECT: usize = 8 * 1024 * 1024;
const MAX_GROUP: u64 = 16 * 1024 * 1024;
const PAUSE_BYTES: u64 = 14 * 1024 * 1024 * 1024;
const MARGIN: u64 = 4 * 1024 * 1024 * 1024;

/// Only a definite capacity refusal before any attempt write is resumable.
/// Existing attempts, read uncertainty and every write-stage failure stay STOPs.
#[derive(Debug)]
pub(crate) enum JobStartError {
    Refused(Error),
    Uncertain(Error),
}

pub(crate) struct Store {
    root: PathBuf,
    margin: PathBuf,
    directory: File,
    _lock: File,
    used: u64,
    head: Option<Digest>,
    poisoned: bool,
}
impl Store {
    pub fn create(root: &Path, margin: &Path) -> Result<Self> {
        if fs2::available_space(margin)? < MARGIN {
            return Err(Error::Paused("host free margin"));
        }
        DirBuilder::new().mode(0o700).create(root)?;
        Self::open(root, margin)
    }
    pub fn open(root: &Path, margin: &Path) -> Result<Self> {
        Self::open_inner(root, margin, None)
    }
    pub fn open_pinned(root: &Path, margin: &Path, expected_head: Digest) -> Result<Self> {
        Self::open_inner(root, margin, Some(expected_head))
    }
    fn open_inner(root: &Path, margin: &Path, expected_head: Option<Digest>) -> Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(Error::Unavailable(
                "store requires private regular directory",
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(expected_head.is_none())
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join("LOCK"))?;
        if !lock.metadata()?.is_file() || lock.metadata()?.nlink() != 1 {
            return Err(Error::Unavailable("store lock type"));
        }
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| Error::Unavailable("store already owned"))?;
        let mut used = 4096_u64;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let m = fs::symlink_metadata(entry.path())?;
            if !m.is_file() || m.nlink() != 1 || m.uid() != metadata.uid() {
                return Err(Error::Unavailable("store contains non-owned regular file"));
            }
            used = used
                .checked_add(charge(m.len()))
                .ok_or(Error::Paused("store accounting overflow"))?;
        }
        let mut s = Self {
            root: root.to_owned(),
            margin: margin.to_owned(),
            directory,
            _lock: lock,
            used,
            head: None,
            poisoned: false,
        };
        match s.pointer("HEAD") {
            Ok(head) => s.head = head,
            Err(Error::Unavailable(
                "head encoding"
                | "head length"
                | "head noncanonical hex"
                | "store object type/length"
                | "changed store object",
            )) => s.poisoned = true,
            Err(e) => return Err(e),
        }
        if expected_head.is_some() && s.head != expected_head {
            return Err(Error::Unavailable(
                "independently retained local head mismatch",
            ));
        }
        Ok(s)
    }
    pub fn head(&self) -> Option<Digest> {
        self.head
    }
    pub fn previous(&self) -> Result<Option<Digest>> {
        self.pointer("PREVIOUS")
    }
    pub fn restore_verified(&mut self, id: Digest) -> Result<()> {
        // Recovery gets its own bounded reservation; it never makes normal
        // writes usable while an incomplete/corrupt generation is current.
        self.poisoned = false;
        if let Err(e) = self.reserve(4 * 4096) {
            self.poisoned = true;
            return Err(e);
        }
        self.used += 4 * 4096;
        self.poisoned = true;
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("recovery quarantine entropy"))?;
        let quarantine = format!("quarantined-head-{}", hex::encode(nonce));
        match rustix::fs::renameat_with(
            &self.directory,
            "HEAD",
            &self.directory,
            quarantine.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => self.directory.sync_all()?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(std::io::Error::from(e).into()),
        }
        self.replace_pointer("HEAD", id)?;
        self.directory.sync_all()?;
        self.head = Some(id);
        self.poisoned = false;
        if fs2::available_space(&self.margin)? < MARGIN {
            self.poisoned = true;
            return Err(Error::Paused("post-recovery host margin"));
        }
        Ok(())
    }
    fn pointer(&self, name: &str) -> Result<Option<Digest>> {
        match self.read_name(name, 64) {
            Ok(b) if b.len() == 64 => {
                let text =
                    std::str::from_utf8(&b).map_err(|_| Error::Unavailable("head encoding"))?;
                let bytes = hex::decode(text).map_err(|_| Error::Unavailable("head encoding"))?;
                let id: Digest = bytes
                    .try_into()
                    .map_err(|_| Error::Unavailable("head length"))?;
                if hex::encode(id).as_bytes() != b {
                    return Err(Error::Unavailable("head noncanonical hex"));
                }
                Ok(Some(id))
            }
            Ok(_) => Err(Error::Unavailable("head length")),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn read_name(&self, name: &str, limit: usize) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.root.join(name))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit as u64 {
            return Err(Error::Unavailable("store object type/length"));
        }
        let mut b = Vec::with_capacity(meta.len() as usize);
        file.take(limit as u64 + 1).read_to_end(&mut b)?;
        if b.len() as u64 != meta.len() {
            return Err(Error::Unavailable("changed store object"));
        }
        Ok(b)
    }
    pub fn object(&self, id: Digest) -> Result<Vec<u8>> {
        let b = self.read_name(&format!("{}.obj", hex::encode(id)), MAX_OBJECT)?;
        if raw_hash(&b) != id {
            return Err(Error::Unavailable("content object hash"));
        }
        Ok(b)
    }
    fn reserve(&self, bytes: u64) -> Result<()> {
        if self.poisoned {
            return Err(Error::Unavailable(
                "store requires reopen after failed write",
            ));
        }
        let mut accounted = self.used;
        // The qualified runtime places every role's mutable files on the same
        // capped task filesystem, distinct from the host margin filesystem.
        if self.directory.metadata()?.dev() != fs::metadata(&self.margin)?.dev() {
            let volume_used =
                fs2::total_space(&self.root)?.saturating_sub(fs2::available_space(&self.root)?);
            accounted = accounted.max(volume_used);
        }
        if bytes > MAX_GROUP || accounted.checked_add(bytes).is_none_or(|v| v > PAUSE_BYTES) {
            return Err(Error::Paused("persistent quota reservation"));
        }
        if fs2::available_space(&self.margin)? < MARGIN {
            return Err(Error::Paused("host free margin"));
        }
        if fs2::available_space(&self.root)? < bytes {
            return Err(Error::Paused("store free capacity"));
        }
        Ok(())
    }
    pub fn check_external_write(&self, bytes: usize) -> Result<()> {
        self.reserve(charge(bytes as u64) + 4096)
    }
    /// The caller orders full-data objects before state/delta/index objects; all
    /// are durable before the head. The previous complete generation is retained.
    pub fn commit(&mut self, objects: &[&[u8]], head: &[u8]) -> Result<Digest> {
        let total =
            objects
                .iter()
                .chain(std::iter::once(&head))
                .try_fold(4 * 4096_u64, |sum, b| {
                    if b.len() > MAX_OBJECT {
                        return Err(Error::Paused("snapshot object chunk"));
                    }
                    sum.checked_add(charge(b.len() as u64))
                        .ok_or(Error::Paused("commit group overflow"))
                })?;
        self.reserve(total)?;
        // Charge the reservation even on partial failure; reopening performs an
        // exact inventory and includes every failed/unreachable temporary file.
        self.used += total;
        self.poisoned = true;
        for object in objects {
            self.put(object)?;
        }
        let id = self.put(head)?;
        self.directory.sync_all()?;
        if let Some(previous) = self.head {
            self.replace_pointer("PREVIOUS", previous)?;
            self.directory.sync_all()?;
        }
        self.replace_pointer("HEAD", id)?;
        self.directory.sync_all()?;
        self.head = Some(id);
        self.poisoned = false;
        // A shared host can lose space between reservation and publication.
        // Preserve the new complete head but refuse further work on that breach.
        if fs2::available_space(&self.margin)? < MARGIN {
            self.poisoned = true;
            return Err(Error::Paused("post-commit host margin"));
        }
        Ok(id)
    }
    fn put(&self, b: &[u8]) -> Result<Digest> {
        let id = raw_hash(b);
        let name = format!("{}.obj", hex::encode(id));
        match self.object(id) {
            Ok(existing) if existing == b => return Ok(id),
            Ok(_) => return Err(Error::Unavailable("existing object changed")),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Never expose a partial write under its canonical content-addressed name.
        // A crash leaves a uniquely named, counted stage object, not a poisoned
        // destination that would prevent retrying the same legitimate transition.
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("object temporary entropy"))?;
        let stage = format!("object-stage-{}", hex::encode(nonce));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.root.join(&stage))?;
        file.write_all(b)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            &self.directory,
            stage.as_str(),
            &self.directory,
            name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        Ok(id)
    }
    fn replace_pointer(&self, name: &str, id: Digest) -> Result<()> {
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("head temporary entropy"))?;
        let temporary = self.root.join(format!("stage-{}", hex::encode(nonce)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(hex::encode(id).as_bytes())?;
        file.sync_all()?;
        fs::rename(temporary, self.root.join(name))?;
        Ok(())
    }
    pub fn accounted_bytes(&self) -> u64 {
        self.used
    }
    /// An interrupted job is NEVER automatically retried under a new allowance.
    /// The marker points to retained canonical input, not a partly valid result.
    pub fn active_job(&self) -> Result<Option<(Digest, Vec<u8>)>> {
        self.active_marker("ACTIVE_JOB")
    }
    pub fn active_replay(&self) -> Result<Option<(Digest, Vec<u8>)>> {
        self.active_marker("ACTIVE_REPLAY")
    }
    fn active_marker(&self, name: &str) -> Result<Option<(Digest, Vec<u8>)>> {
        self.pointer(name)?
            .map(|id| Ok((id, self.object(id)?)))
            .transpose()
    }
    pub fn begin_job(&mut self, bytes: &[u8]) -> std::result::Result<Digest, JobStartError> {
        let charged = self
            .preflight_marker("ACTIVE_JOB", bytes)
            .map_err(|error| {
                if matches!(
                    error,
                    Error::Paused(
                        "persistent quota reservation" | "host free margin" | "store free capacity"
                    )
                ) {
                    JobStartError::Refused(error)
                } else {
                    JobStartError::Uncertain(error)
                }
            })?;
        self.write_marker("ACTIVE_JOB", bytes, charged)
            .map_err(JobStartError::Uncertain)
    }
    pub fn begin_replay(&mut self, bytes: &[u8]) -> Result<Digest> {
        // A freshly opened malformed HEAD can only be repaired after a bounded
        // authenticated replay. Permit ONLY its separate attempt marker here;
        // preserve the poisoned status and never overwrite/adopt the bad HEAD.
        let was_poisoned = self.poisoned;
        self.poisoned = false;
        let result = self.begin_marker("ACTIVE_REPLAY", bytes);
        self.poisoned |= was_poisoned;
        result
    }
    fn begin_marker(&mut self, name: &str, bytes: &[u8]) -> Result<Digest> {
        let charged = self.preflight_marker(name, bytes)?;
        self.write_marker(name, bytes, charged)
    }
    fn preflight_marker(&self, name: &str, bytes: &[u8]) -> Result<u64> {
        if self.active_marker(name)?.is_some() {
            return Err(Error::Paused(
                "incomplete local job requires explicit bounded authority",
            ));
        }
        let charged = charge(bytes.len() as u64) + 4 * 4096;
        self.reserve(charged)?;
        Ok(charged)
    }
    fn write_marker(&mut self, name: &str, bytes: &[u8], charged: u64) -> Result<Digest> {
        self.used += charged;
        self.poisoned = true;
        let id = self.put(bytes)?;
        self.directory.sync_all()?;
        self.replace_pointer(name, id)?;
        self.directory.sync_all()?;
        self.poisoned = false;
        if fs2::available_space(&self.margin)? < MARGIN {
            self.poisoned = true;
            return Err(Error::Paused("post-job-marker host margin"));
        }
        Ok(id)
    }
    pub fn finish_job(&mut self, id: Digest, accepted: bool) -> Result<()> {
        self.finish_marker("ACTIVE_JOB", "finished-job-", b"SNF04JT1", id, accepted)
    }
    pub fn finish_replay(&mut self, id: Digest) -> Result<()> {
        self.finish_marker("ACTIVE_REPLAY", "finished-replay-", b"SNF04RT1", id, true)
    }
    fn finish_marker(
        &mut self,
        active: &str,
        prefix: &str,
        magic: &[u8; 8],
        id: Digest,
        accepted: bool,
    ) -> Result<()> {
        if self.pointer(active)? != Some(id) {
            return Err(Error::Unavailable("active admission identity changed"));
        }
        self.reserve(4 * 4096)?;
        self.used += 4 * 4096;
        self.poisoned = true;
        let mut terminal = Vec::from(magic.as_slice());
        terminal.extend_from_slice(&id);
        terminal.push(u8::from(accepted));
        terminal.extend_from_slice(
            &self
                .head
                .ok_or(Error::Unavailable("missing terminal head"))?,
        );
        let receipt = self.put(&terminal)?;
        self.directory.sync_all()?;
        // Preserve the marker as evidence instead of deleting it. Unique attempt
        // nonce in its contents prevents collision across repeated invalid inputs.
        let name = format!("{prefix}{}", hex::encode(receipt));
        rustix::fs::renameat_with(
            &self.directory,
            active,
            &self.directory,
            name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        self.directory.sync_all()?;
        self.poisoned = false;
        if fs2::available_space(&self.margin)? < MARGIN {
            self.poisoned = true;
            return Err(Error::Paused("post-job-terminal host margin"));
        }
        Ok(())
    }
}
fn charge(bytes: u64) -> u64 {
    bytes.saturating_add(4095) / 4096 * 4096 + 4096
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_open_refuses_changed_head_or_missing_lock_without_adoption() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pinned");
        let mut s = Store::create(&root, dir.path()).unwrap();
        let head = s.commit(&[b"data"], b"head").unwrap();
        drop(s);
        let names = || {
            let mut n = fs::read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>();
            n.sort();
            n
        };
        let before = names();
        assert!(Store::open_pinned(&root, dir.path(), [1; 32]).is_err());
        assert_eq!(names(), before);
        assert_eq!(
            Store::open_pinned(&root, dir.path(), head).unwrap().head(),
            Some(head)
        );
        fs::rename(root.join("LOCK"), root.join("retained-lock")).unwrap();
        assert!(Store::open_pinned(&root, dir.path(), head).is_err());
        assert!(!root.join("LOCK").exists());
    }
    #[test]
    fn immutable_objects_atomic_heads_lock_and_unreachable_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("node");
        let mut s = Store::create(&root, dir.path()).unwrap();
        assert!(Store::open(&root, dir.path()).is_err());
        let h1 = s.commit(&[b"full data", b"state"], b"head1").unwrap();
        let h2 = s.commit(&[b"next state"], b"head2").unwrap();
        assert_eq!(s.previous().unwrap(), Some(h1));
        assert_eq!(s.head(), Some(h2));
        assert_eq!(s.object(raw_hash(b"full data")).unwrap(), b"full data");
        s.put(b"unreachable but retained").unwrap();
        drop(s);
        let s = Store::open(&root, dir.path()).unwrap();
        assert_eq!(s.head(), Some(h2));
        assert!(s.accounted_bytes() > 0);
        assert_eq!(
            s.object(raw_hash(b"unreachable but retained")).unwrap(),
            b"unreachable but retained"
        );
    }
    #[test]
    fn interrupted_job_stays_durable_and_terminal_retains_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("node");
        let mut store = Store::create(&root, dir.path()).unwrap();
        let head = store.commit(&[b"data"], b"complete head").unwrap();
        let job = store
            .begin_job(b"bounded unverified canonical input")
            .unwrap();
        assert!(matches!(
            store.begin_job(b"new attempt"),
            Err(JobStartError::Uncertain(Error::Paused(_)))
        ));
        drop(store);
        let mut store = Store::open(&root, dir.path()).unwrap();
        assert_eq!(
            store.active_job().unwrap(),
            Some((job, b"bounded unverified canonical input".to_vec()))
        );
        assert_eq!(store.head(), Some(head));
        store.finish_job(job, false).unwrap();
        assert!(store.active_job().unwrap().is_none());
        assert_eq!(
            store.object(job).unwrap(),
            b"bounded unverified canonical input"
        );
        assert!(fs::read_dir(&root).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("finished-job-")
        }));
    }
    #[test]
    fn replay_attempt_is_separate_retained_and_cannot_replenish_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("replay");
        let mut store = Store::create(&root, dir.path()).unwrap();
        let head = store.commit(&[], b"complete").unwrap();
        let job = store.begin_job(b"foreground attempt").unwrap();
        let replay = store.begin_replay(b"retained replay attempt").unwrap();
        assert!(store.begin_replay(b"another replay allowance").is_err());
        assert_eq!(store.head(), Some(head));
        drop(store);
        let mut store = Store::open_pinned(&root, dir.path(), head).unwrap();
        assert_eq!(store.active_replay().unwrap().unwrap().0, replay);
        assert_eq!(store.active_job().unwrap().unwrap().0, job);
        assert!(store.begin_replay(b"renewed after restart").is_err());
        // Store-layer completion primitive; caller must establish replay success.
        store.finish_replay(replay).unwrap();
        assert!(store.active_replay().unwrap().is_none());
        assert_eq!(store.active_job().unwrap().unwrap().0, job);
        assert_eq!(store.head(), Some(head));
        assert!(store.object(replay).is_ok());
    }
    #[test]
    fn poisoned_head_allows_only_separate_replay_marker_before_verified_repair() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("recovery");
        let mut store = Store::create(&root, dir.path()).unwrap();
        let previous = store.commit(&[], b"previous complete").unwrap();
        store.commit(&[], b"later complete").unwrap();
        drop(store);
        fs::write(root.join("HEAD"), b"malformed").unwrap();
        let mut store = Store::open(&root, dir.path()).unwrap();
        assert!(store.commit(&[], b"must not publish").is_err());
        let replay = store.begin_replay(b"bounded repair replay").unwrap();
        assert_eq!(fs::read(root.join("HEAD")).unwrap(), b"malformed");
        assert!(store.commit(&[], b"still unavailable").is_err());
        assert_eq!(store.previous().unwrap(), Some(previous));
        // Caller-owned verification capability is outside this store-layer test.
        store.restore_verified(previous).unwrap();
        store.finish_replay(replay).unwrap();
        assert_eq!(store.head(), Some(previous));
        assert!(store.active_replay().unwrap().is_none());
    }
}
