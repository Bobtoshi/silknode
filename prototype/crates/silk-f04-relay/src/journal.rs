//! Bounded local terminal journal. Persistence receipts are NOT timed send permits.
//! Reopen requires an independently retained exact pin; no recovered round resumes.
use crate::{
    Digest, Error, Result,
    config::SignedConfig,
    control::{AuthorizationEvidence, FENCE, PreparedAuthorization, ReleaseEvidence, Role},
    field,
    manifest::{SignedManifest, check_body},
    u32le, u64le,
};
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags};
use silk_sapling_f04::codec::domain_hash;
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const BYTES: usize = 4096;
const SLOT: usize = 1920;
const HEADER: usize = 256;

/// Persisted local outcome; none grants post-restart signing or key recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    /// Begun before the first manifest signature.
    Open = 1,
    /// A's irrevocable terminal authorization body is durable.
    SealedAuth = 2,
    /// Terminal no-release decision (A or B).
    Abort = 3,
    /// B's authorization observation has closed.
    AuthFrozen = 4,
    /// B committed before the first key-bearing write.
    ReleaseDecided = 5,
    /// All scheduled writes completed locally; not simultaneous peer receipt.
    Finalized = 6,
    /// Some key bytes may have left; never retry or reconstruct the key.
    DeliveryUnknown = 7,
}
impl Decision {
    const fn closed(self) -> bool {
        matches!(
            self,
            Self::SealedAuth | Self::Abort | Self::Finalized | Self::DeliveryUnknown
        )
    }
    const fn decode(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Open),
            2 => Ok(Self::SealedAuth),
            3 => Ok(Self::Abort),
            4 => Ok(Self::AuthFrozen),
            5 => Ok(Self::ReleaseDecided),
            6 => Ok(Self::Finalized),
            7 => Ok(Self::DeliveryUnknown),
            _ => Err(Error::Unavailable("journal decision")),
        }
    }
}

/// Local persistence only. The caller must retain `pin()` independently after
/// EACH mutation, before relying on continuity. Losing it is a local STOP.
///
/// Exactly CURRENT(4096), optional STAGE(4096), LOCK(0), and directory metadata.
/// No secret-bearing control, session, permutation, cell, or key is serializable.
pub struct Journal {
    directory: File,
    // Optional explicitly separate host filesystem; never serialized authority.
    host_margin: Option<File>,
    lock: File,
    bytes: [u8; BYTES],
    pin: Digest,
    live: [Option<u64>; 2],
    earliest: u64,
    poisoned: bool,
}
impl Journal {
    #[cfg(feature = "functional-lab")]
    pub(crate) fn functional_identity(&self) -> Result<(u64, u64)> {
        let metadata = self.lock.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    /// Initialize an explicitly new, empty, owned0700 directory. Never reset it.
    /// `utc_round` is an independently trusted clock observation, not peer data.
    /// # Errors
    /// Refuses unsupported role, residue, ownership, capacity or I/O uncertainty.
    pub fn create(
        path: &Path,
        domain: Digest,
        cohort: u32,
        role: Role,
        utc_round: u64,
    ) -> Result<Self> {
        Self::create_inner(path, None, domain, cohort, role, utc_round)
    }
    /// Create on an externally capped store while retaining the unchanged4GiB
    /// host-space guard on an explicitly separate filesystem. The store must
    /// additionally have64KiB free for the fixed journal/staging metadata.
    /// This selects no runtime cap, default or ledger authority.
    /// # Errors
    /// Refuses non-directory/symlink/same-filesystem margins, capacity and all
    /// ordinary owned-directory, residue, role and persistence failures.
    pub fn create_with_host_margin(
        path: &Path,
        host_margin: &Path,
        domain: Digest,
        cohort: u32,
        role: Role,
        utc_round: u64,
    ) -> Result<Self> {
        Self::create_inner(path, Some(host_margin), domain, cohort, role, utc_round)
    }
    fn create_inner(
        path: &Path,
        margin: Option<&Path>,
        domain: Digest,
        cohort: u32,
        role: Role,
        utc_round: u64,
    ) -> Result<Self> {
        check_role(role)?;
        let directory = open_dir(path)?;
        let host_margin = open_margin(margin, &directory)?;
        inventory(&directory, false)?;
        let lock = fresh(&directory, "LOCK")?;
        lock_file(&lock)?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"SNJRLF04");
        bytes[8] = role as u8;
        bytes[40..48].copy_from_slice(&utc_round.to_le_bytes());
        bytes[48..80].copy_from_slice(&domain);
        bytes[80..84].copy_from_slice(&cohort.to_le_bytes());
        let mut journal = Self {
            directory,
            host_margin,
            lock,
            bytes,
            pin: [0; 32],
            live: [None; 2],
            earliest: future_floor(None, utc_round)?,
            poisoned: true,
        };
        journal.publish(&bytes, false)?;
        Ok(journal)
    }

    /// Authenticate exact latest storage, then durably close interrupted states.
    /// Recovered `RELEASE_DECIDED` becomes `DELIVERY_UNKNOWN`. No old round is live.
    /// Clock/config/admission must be independently re-established by the driver.
    /// # Errors
    /// Missing/corrupt/rolled-back/residual storage and backward clocks STOP.
    pub fn open(
        path: &Path,
        domain: Digest,
        cohort: u32,
        role: Role,
        expected_pin: Digest,
        utc_round: u64,
    ) -> Result<Self> {
        Self::open_inner(path, None, domain, cohort, role, expected_pin, utc_round)
    }
    /// Pinned cold reopen of the explicit separately-margined capped-store mode.
    /// No old round resumes and no stored byte can select its host filesystem.
    /// # Errors
    /// Refuses margin, capacity and every ordinary continuity/recovery failure.
    pub fn open_with_host_margin(
        path: &Path,
        host_margin: &Path,
        domain: Digest,
        cohort: u32,
        role: Role,
        expected_pin: Digest,
        utc_round: u64,
    ) -> Result<Self> {
        Self::open_inner(
            path,
            Some(host_margin),
            domain,
            cohort,
            role,
            expected_pin,
            utc_round,
        )
    }
    fn open_inner(
        path: &Path,
        margin: Option<&Path>,
        domain: Digest,
        cohort: u32,
        role: Role,
        expected_pin: Digest,
        utc_round: u64,
    ) -> Result<Self> {
        check_role(role)?;
        let directory = open_dir(path)?;
        let host_margin = open_margin(margin, &directory)?;
        let lock = existing(&directory, "LOCK", 0)?;
        lock_file(&lock)?;
        inventory(&directory, true)?;
        let mut file = existing(&directory, "CURRENT", BYTES as u64)?;
        let mut bytes = [0; BYTES];
        file.read_exact(&mut bytes)?;
        let mut extra = [0];
        if file.read(&mut extra)? != 0 || digest(&bytes) != expected_pin {
            return Err(Error::Unavailable("journal continuity pin"));
        }
        validate(&bytes, domain, cohort, role)?;
        if utc_round < u64le(&bytes, 40)? {
            return Err(Error::Unavailable("journal trusted clock rollback"));
        }
        let highest = (bytes[9] & 1 != 0).then(|| u64le(&bytes, 24)).transpose()?;
        if highest.is_some_and(|r| r > utc_round.saturating_add(1)) {
            return Err(Error::Unavailable("journal clock/high-water inconsistency"));
        }
        let mut journal = Self {
            directory,
            host_margin,
            lock,
            bytes,
            pin: expected_pin,
            live: [None; 2],
            earliest: future_floor(highest, utc_round)?,
            poisoned: false,
        };
        let mut next = bytes;
        for i in 0..2 {
            let at = HEADER + SLOT * i;
            if next[at] == 0 {
                continue;
            }
            let decision = Decision::decode(next[at])?;
            next[at] = match decision {
                Decision::Open | Decision::AuthFrozen => Decision::Abort as u8,
                Decision::ReleaseDecided => Decision::DeliveryUnknown as u8,
                other => other as u8,
            };
            close_high_water(&mut next, u64le(&bytes, at + 8)?)?;
        }
        next[40..48].copy_from_slice(&utc_round.to_le_bytes());
        journal.commit(next)?;
        Ok(journal)
    }

    /// Exact latest snapshot digest; retain outside this rollback domain.
    #[must_use]
    pub const fn pin(&self) -> Digest {
        self.pin
    }
    /// Immutable role established at creation and checked again on pinned reopen.
    #[must_use]
    pub const fn role(&self) -> Role {
        if self.bytes[8] == Role::A as u8 {
            Role::A
        } else {
            Role::B
        }
    }
    /// Conservative strict reading of "after max(highest+1,UTC+2)".
    /// This intentionally adds local unavailability rather than loosening restart.
    #[must_use]
    pub const fn earliest_round(&self) -> u64 {
        self.earliest
    }

    /// Reserve one of exactly two current/next slots BEFORE manifest signing.
    /// The exact unsigned M cannot change for a started round. A mature-cut check
    /// and admitted immutable clock still belong to the role coordinator.
    /// # Errors
    /// Refuses stale/conflicting rounds, changed context or more than two live slots.
    pub fn begin(
        &mut self,
        config: &SignedConfig,
        round: u64,
        manifest_body: &[u8; 128],
        utc_round: u64,
    ) -> Result<()> {
        self.ready()?;
        check_body(manifest_body, config, round)?;
        if config.domain() != field::<32>(&self.bytes, 48)?
            || config.cohort() != u32le(&self.bytes, 80)?
            || utc_round < u64le(&self.bytes, 40)?
            || round < self.earliest
            || round
                > utc_round
                    .checked_add(1)
                    .ok_or(Error::Unavailable("round overflow"))?
            || round < utc_round
        {
            return Err(Error::Unavailable("journal start clock/context"));
        }
        if self.bytes[9] & 1 != 0 && round <= u64le(&self.bytes, 24)? {
            return Err(Error::Unavailable("journal round already started"));
        }
        // A terminal decision may still belong to the current live round.
        // In particular SEALED_AUTH at+18.5 must survive successor admission
        // at+20 until the current owner's+22 material cleanup and retirement.
        let index = (0..2)
            .find(|i| self.live[*i].is_none() && self.bytes[HEADER + SLOT * i] == 0)
            .or_else(|| {
                (0..2)
                    .filter(|i| {
                        self.live[*i].is_none()
                            && Decision::decode(self.bytes[HEADER + SLOT * i])
                                .is_ok_and(Decision::closed)
                    })
                    .min_by_key(|i| u64le(&self.bytes, HEADER + SLOT * i + 8).ok())
            })
            .ok_or(Error::Unavailable("journal two-round capacity"))?;
        let mut next = self.bytes;
        let at = HEADER + SLOT * index;
        next[at..at + SLOT].fill(0);
        next[at] = Decision::Open as u8;
        next[at + 8..at + 16].copy_from_slice(&round.to_le_bytes());
        next[at + 16..at + 48].copy_from_slice(&config.id());
        next[at + 48..at + 52].copy_from_slice(&config.epoch().to_le_bytes());
        next[at + 56..at + 184].copy_from_slice(manifest_body);
        next[9] |= 1;
        next[24..32].copy_from_slice(&round.to_le_bytes());
        next[40..48].copy_from_slice(&utc_round.to_le_bytes());
        self.commit(next)?;
        self.live[index] = Some(round);
        Ok(())
    }

    /// Bind complete co-signed M only to its already-durable exact proposal.
    /// # Errors
    /// Refuses recovered, foreign or conflicting manifests.
    pub fn manifested(&mut self, manifest: &SignedManifest) -> Result<()> {
        let at = self.live_slot(manifest.round())?;
        if self.bytes[at] != Decision::Open as u8
            || self.bytes[at + 16..at + 48] != manifest.config()
            || self.bytes[at + 56..at + 184] != manifest.bytes()[..128]
            || (self.bytes[at + 184..at + 216] != [0; 32]
                && self.bytes[at + 184..at + 216] != manifest.id())
        {
            return Err(Error::Unavailable("journal manifest commitment"));
        }
        if self.bytes[at + 184..at + 216] == manifest.id() {
            return Ok(());
        }
        let mut next = self.bytes;
        next[at + 184..at + 216].copy_from_slice(&manifest.id());
        self.commit(next)
    }

    /// A: persist exact unsigned authorization BEFORE its live signing step.
    /// This is not evidence that the +18.5 observation barrier passed.
    /// # Errors
    /// Refuses any non-A/open/live state or mismatched complete manifest.
    pub fn seal_a(&mut self, prepared: &PreparedAuthorization) -> Result<()> {
        self.store_auth(prepared.body(), [0; 32], Role::A, Decision::SealedAuth)
    }
    /// B: persist complete checked authorization after its receipt barrier.
    /// # Errors
    /// Refuses any non-B/open/live state or mismatched complete manifest.
    pub fn freeze_b(&mut self, evidence: &AuthorizationEvidence<'_>) -> Result<()> {
        let body = evidence.control().bytes()[..448]
            .try_into()
            .map_err(|_| Error::Invalid("authorization body length"))?;
        self.store_auth(body, evidence.control().id(), Role::B, Decision::AuthFrozen)
    }
    fn store_auth(
        &mut self,
        body: &[u8; 448],
        reference: Digest,
        role: Role,
        decision: Decision,
    ) -> Result<()> {
        let round = u64le(body, 80)?;
        let at = self.live_slot(round)?;
        if self.bytes[8] != role as u8 || self.bytes[at] != Decision::Open as u8 {
            return Err(Error::Unavailable("journal authorization transition"));
        }
        check_auth(body, &self.bytes, at)?;
        let mut next = self.bytes;
        next[at] = decision as u8;
        next[at + 216..at + 664].copy_from_slice(body);
        next[at + 664..at + 696].copy_from_slice(&reference);
        if decision.closed() {
            close_high_water(&mut next, round)?;
        }
        self.commit(next)
    }
    /// Record a live signed-control reference only, never its secret-bearing bytes.
    /// B's immutable release bytes remain volatile; this records the pre-write fence.
    /// # Errors
    /// Refuses anything except live B `AUTH_FROZEN`. Timing/local health are external.
    pub fn release_decided(&mut self, evidence: &ReleaseEvidence<'_>) -> Result<()> {
        let control = evidence.control().bytes();
        let round = u64le(control, 80)?;
        let at = self.live_slot(round)?;
        if self.bytes[8] != Role::B as u8 || self.bytes[at] != Decision::AuthFrozen as u8 {
            return Err(Error::Unavailable("journal release transition"));
        }
        let frozen = &self.bytes[at + 216..at + 664];
        if control[10..288] != frozen[10..288] || control[320..448] != frozen[320..448] {
            return Err(Error::Unavailable(
                "journal release/frozen authorization mismatch",
            ));
        }
        let mut next = self.bytes;
        next[at] = Decision::ReleaseDecided as u8;
        next[at + 696..at + 728].copy_from_slice(&evidence.control().id());
        self.commit(next)
    }
    /// Close local release delivery, never retry/recall. This does not prove receipt.
    /// # Errors
    /// Refuses any non-live B release decision.
    pub fn delivery(&mut self, round: u64, complete: bool) -> Result<()> {
        let at = self.live_slot(round)?;
        if self.bytes[8] != Role::B as u8 || self.bytes[at] != Decision::ReleaseDecided as u8 {
            return Err(Error::Unavailable("journal delivery transition"));
        }
        let mut next = self.bytes;
        next[at] = if complete {
            Decision::Finalized
        } else {
            Decision::DeliveryUnknown
        } as u8;
        close_high_water(&mut next, round)?;
        self.commit(next)
    }
    /// Abort only before irrevocable authorization/release commitment.
    /// # Errors
    /// A `SEALED_AUTH` and B `RELEASE_DECIDED` can never transition to abort.
    pub fn abort(&mut self, round: u64) -> Result<()> {
        let at = self.live_slot(round)?;
        if !matches!(
            Decision::decode(self.bytes[at])?,
            Decision::Open | Decision::AuthFrozen
        ) {
            return Err(Error::Unavailable(
                "journal cannot revoke terminal decision",
            ));
        }
        let mut next = self.bytes;
        next[at] = Decision::Abort as u8;
        close_high_water(&mut next, round)?;
        self.commit(next)
    }
    /// Live-only cancellation context. A retained/reopened Abort is evidence,
    /// never authority: `live_slot` must succeed even when no new write is needed.
    pub(crate) fn cancel_live(&mut self, config: &SignedConfig, round: u64) -> Result<Digest> {
        let at = self.live_slot(round)?;
        if self.bytes[at + 16..at + 48] != config.id() {
            return Err(Error::Unavailable("live cancellation configuration"));
        }
        let manifest = field(&self.bytes, at + 184)?;
        match Decision::decode(self.bytes[at])? {
            Decision::Open | Decision::AuthFrozen => self.abort(round)?,
            Decision::Abort => (),
            _ => {
                return Err(Error::Unavailable(
                    "live cancellation cannot revoke decision",
                ));
            }
        }
        Ok(manifest)
    }
    /// Release only volatile authority after the owner erases round material.
    /// Terminal bytes and both persistent high-water marks are retained.
    pub(crate) fn retire_live(&mut self, config: &SignedConfig, round: u64) -> Result<()> {
        let at = self.live_slot(round)?;
        if self.bytes[at + 16..at + 48] != config.id()
            || !Decision::decode(self.bytes[at])?.closed()
        {
            return Err(Error::Unavailable(
                "live retirement requires terminal context",
            ));
        }
        self.live[(at - HEADER) / SLOT] = None;
        Ok(())
    }
    /// Inspect an outcome without reconstructing an old signing/release capability.
    #[must_use]
    pub fn decision(&self, round: u64) -> Option<Decision> {
        (0..2).find_map(|i| {
            let at = HEADER + SLOT * i;
            (self.bytes[at] != 0 && u64le(&self.bytes, at + 8).ok() == Some(round))
                .then(|| Decision::decode(self.bytes[at]).ok())
                .flatten()
        })
    }
    fn ready(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Unavailable("poisoned relay journal"));
        }
        self.poisoned = true;
        inventory(&self.directory, true)?;
        let lock = existing(&self.directory, "LOCK", 0)?;
        let expected_lock = self.lock.metadata()?;
        let actual_lock = lock.metadata()?;
        if actual_lock.dev() != expected_lock.dev() || actual_lock.ino() != expected_lock.ino() {
            return Err(Error::Unavailable("live journal lock identity changed"));
        }
        let mut current = existing(&self.directory, "CURRENT", BYTES as u64)?;
        let mut bytes = [0; BYTES];
        current.read_exact(&mut bytes)?;
        if digest(&bytes) != self.pin {
            return Err(Error::Unavailable("live journal continuity changed"));
        }
        self.poisoned = false;
        Ok(())
    }
    fn live_slot(&mut self, round: u64) -> Result<usize> {
        self.ready()?;
        self.live
            .iter()
            .position(|r| *r == Some(round))
            .map(|i| HEADER + SLOT * i)
            .ok_or(Error::Unavailable("journal recovered/stale round"))
    }
    fn commit(&mut self, mut next: [u8; BYTES]) -> Result<()> {
        self.ready()?;
        let generation = u64le(&self.bytes, 16)?
            .checked_add(1)
            .ok_or(Error::Unavailable("journal generation overflow"))?;
        next[16..24].copy_from_slice(&generation.to_le_bytes());
        next[96..128].copy_from_slice(&self.pin);
        self.poisoned = true;
        self.publish(&next, true)
    }
    fn publish(&mut self, next: &[u8; BYTES], replace: bool) -> Result<()> {
        let space = rustix::fs::fstatvfs(&self.directory).map_err(std::io::Error::from)?;
        if !has_space(space.f_bavail, space.f_frsize, 64 * 1024) {
            return Err(Error::Unavailable("journal store capacity"));
        }
        let margin = self.host_margin.as_ref().unwrap_or(&self.directory);
        let space = rustix::fs::fstatvfs(margin).map_err(std::io::Error::from)?;
        if !has_space(space.f_bavail, space.f_frsize, 4 * 1024 * 1024 * 1024) {
            return Err(Error::Unavailable("journal host margin"));
        }
        let mut stage = fresh(&self.directory, "STAGE")?;
        stage.write_all(next)?;
        stage.sync_all()?;
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
        self.directory.sync_all()?;
        self.bytes = *next;
        self.pin = digest(next);
        self.poisoned = false;
        Ok(())
    }
}

const fn check_role(role: Role) -> Result<()> {
    if matches!(role, Role::A | Role::B) {
        Ok(())
    } else {
        Err(Error::Unavailable("journal relay role"))
    }
}
fn future_floor(highest: Option<u64>, utc: u64) -> Result<u64> {
    let next = highest
        .map_or(Some(0), |r| r.checked_add(1))
        .ok_or(Error::Unavailable("journal high-water overflow"))?;
    next.max(
        utc.checked_add(2)
            .ok_or(Error::Unavailable("journal clock overflow"))?,
    )
    .checked_add(1)
    .ok_or(Error::Unavailable("journal future-round overflow"))
}
fn close_high_water(bytes: &mut [u8; BYTES], round: u64) -> Result<()> {
    let highest = if bytes[9] & 2 == 0 {
        round
    } else {
        round.max(u64le(bytes, 32)?)
    };
    bytes[9] |= 2;
    bytes[32..40].copy_from_slice(&highest.to_le_bytes());
    Ok(())
}
fn check_auth(body: &[u8; 448], bytes: &[u8; BYTES], at: usize) -> Result<()> {
    if &body[..8] != b"SNCTLF03"
        || body[8..12] != [4, 0, 1, 0]
        || body[12..44] != bytes[48..80]
        || body[44..76] != bytes[at + 16..at + 48]
        || body[76..80] != bytes[80..84]
        || body[80..88] != bytes[at + 8..at + 16]
        || body[88..120] != bytes[at + 184..at + 216]
        || body[88..120] == [0; 32]
        || !(8..=32).contains(&body[248])
        || body[249..256] != [0; 7]
        || body[288..320] != [0; 32]
    {
        return Err(Error::Unavailable(
            "journal nonsecret authorization binding",
        ));
    }
    for (i, fence) in FENCE.iter().enumerate() {
        if u64le(body, 416 + 8 * i)? != *fence {
            return Err(Error::Unavailable("journal fence"));
        }
    }
    Ok(())
}
fn validate(bytes: &[u8; BYTES], domain: Digest, cohort: u32, role: Role) -> Result<()> {
    if &bytes[..8] != b"SNJRLF04"
        || bytes[8] != role as u8
        || bytes[9] > 3
        || bytes[10..16] != [0; 6]
        || bytes[48..80] != domain
        || u32le(bytes, 80)? != cohort
        || bytes[84..96] != [0; 12]
        || bytes[128..HEADER] != [0; 128]
        || (bytes[9] & 1 == 0 && bytes[24..32] != [0; 8])
        || (bytes[9] & 2 == 0 && bytes[32..40] != [0; 8])
        || (bytes[9] & 2 != 0 && (bytes[9] & 1 == 0 || u64le(bytes, 32)? > u64le(bytes, 24)?))
    {
        return Err(Error::Unavailable("journal header"));
    }
    let mut rounds = [None; 2];
    for (i, retained) in rounds.iter_mut().enumerate() {
        let at = HEADER + SLOT * i;
        if bytes[at] == 0 {
            if bytes[at..at + SLOT].iter().any(|b| *b != 0) {
                return Err(Error::Unavailable("journal unused slot"));
            }
            continue;
        }
        let decision = Decision::decode(bytes[at])?;
        let round = u64le(bytes, at + 8)?;
        *retained = Some(round);
        if bytes[at + 1..at + 8] != [0; 7]
            || bytes[at + 52..at + 56] != [0; 4]
            || bytes[at + 728..at + SLOT].iter().any(|b| *b != 0)
            || bytes[9] & 1 == 0
            || round > u64le(bytes, 24)?
            || u64::from(u32le(bytes, at + 48)?) != round / 2880
            || &bytes[at + 56..at + 64] != b"SNRNDF03"
            || bytes[at + 64..at + 96] != domain
            || u32le(bytes, at + 96)? != cohort
            || u64le(bytes, at + 100)? != round
            || bytes[at + 180..at + 184] != [0; 4]
            || (role == Role::A
                && !matches!(
                    decision,
                    Decision::Open | Decision::SealedAuth | Decision::Abort
                ))
            || (role == Role::B && decision == Decision::SealedAuth)
            || (decision.closed() && (bytes[9] & 2 == 0 || round > u64le(bytes, 32)?))
        {
            return Err(Error::Unavailable("journal slot"));
        }
        let body: &[u8; 448] = bytes[at + 216..at + 664]
            .try_into()
            .map_err(|_| Error::Unavailable("journal body length"))?;
        if body != &[0; 448] {
            check_auth(body, bytes, at)?;
        }
        if !matches!(decision, Decision::Open | Decision::Abort) && body == &[0; 448] {
            return Err(Error::Unavailable("journal missing authorization"));
        }
        if decision == Decision::Open && bytes[at + 216..at + 728] != [0; 512] {
            return Err(Error::Unavailable("journal open terminal fields"));
        }
    }
    if rounds[0].is_some() && rounds[0] == rounds[1] {
        return Err(Error::Unavailable("journal repeated round"));
    }
    Ok(())
}
fn digest(bytes: &[u8; BYTES]) -> Digest {
    domain_hash("SilkNode-F04-relay-journal", &[bytes])
}
fn open_dir(path: &Path) -> Result<File> {
    let file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let meta = file.metadata()?;
    if meta.mode() & 0o777 != 0o700 || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Unavailable("journal owned0700 directory"));
    }
    Ok(file)
}
fn has_space(blocks: u64, size: u64, required: u64) -> bool {
    blocks
        .checked_mul(size)
        .is_some_and(|bytes| bytes >= required)
}

#[cfg(test)]
mod capacity_tests {
    use super::has_space;
    #[test]
    fn fixed_store_and_unchanged_host_thresholds_refuse_underflow_and_overflow() {
        for required in [64 * 1024, 4 * 1024 * 1024 * 1024] {
            assert!(!has_space(required - 1, 1, required));
            assert!(has_space(required, 1, required));
            assert!(!has_space(0, 4096, required));
            assert!(!has_space(u64::MAX, 2, required));
        }
    }
}
fn open_margin(path: Option<&Path>, directory: &File) -> Result<Option<File>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let margin: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    if margin.metadata()?.dev() == directory.metadata()?.dev() {
        return Err(Error::Unavailable(
            "journal margin must be a separate filesystem",
        ));
    }
    Ok(Some(margin))
}
fn identity(file: &File, directory: &File, length: u64) -> Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != directory.metadata()?.uid()
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o600
        || meta.len() != length
    {
        return Err(Error::Unavailable("journal owned0600 file/length"));
    }
    Ok(())
}
fn existing(directory: &File, name: &str, length: u64) -> Result<File> {
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
fn fresh(directory: &File, name: &str) -> Result<File> {
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
fn lock_file(file: &File) -> Result<()> {
    rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)?;
    Ok(())
}
fn inventory(directory: &File, initialized: bool) -> Result<()> {
    let mut mask = 0_u8;
    for entry in rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        match entry.file_name().to_bytes() {
            b"." | b".." => (),
            b"CURRENT" if initialized => mask |= 1,
            b"LOCK" if initialized => mask |= 2,
            _ => return Err(Error::Unavailable("journal residue/inventory")),
        }
    }
    if initialized && mask != 3 {
        return Err(Error::Unavailable("journal missing files"));
    }
    Ok(())
}
