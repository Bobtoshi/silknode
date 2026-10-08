//! Durable, default-off sequence fence around successive original IM3 rounds.
//! The caller still owns role qualification, links, clock, capacity and drives
//! every per-role owner; this cannot turn a fixture into an operational service.
use super::*;
use std::path::Path;

/// One locally pinned sequence store for one immutable P/epoch. Its distinct
/// role prevents an unfinished attempt from borrowing another role's journal.
pub struct Im3RoundSequence<P: ClaimPinRetention> {
    store: PreparedScopeStore<P>,
}
impl<P: ClaimPinRetention> Im3RoundSequence<P> {
    /// Create only in a new owned directory, before any original-link owner.
    pub fn create(path: &Path, profile: &PreparedProfile, pins: P) -> Result<Self> {
        let store =
            PreparedScopeStore::create(path, profile.claim_binding(ClaimRole::Im3Sequence), pins)
                .map_err(|_| Error::Unavailable("IM3 sequence create/pin"))?;
        Ok(Self { store })
    }
    /// Cold reopen requires the independently retained latest pin and trusted
    /// restart round. It skips an interrupted round; it never resumes its links.
    pub fn open(
        path: &Path,
        profile: &PreparedProfile,
        expected_pin: Digest,
        trusted_restart_round: u64,
        pins: P,
    ) -> Result<Self> {
        let store = PreparedScopeStore::open(
            path,
            profile.claim_binding(ClaimRole::Im3Sequence),
            expected_pin,
            trusted_restart_round,
            pins,
        )
        .map_err(|_| Error::Unavailable("IM3 sequence cold continuity"))?;
        Ok(Self { store })
    }
    /// External pin custody is not established by reading this snapshot hash.
    pub fn pin(&self) -> Digest {
        self.store.pin()
    }
    /// The store's irreversible floor, not qualification for a new round.
    pub fn earliest_round(&self) -> u64 {
        self.store.earliest_round()
    }
    /// Consume Q/M/r before dispatch. A live unfinished attempt blocks the
    /// next one even if its Rust capability is dropped. Each new even round
    /// requires a fresh original schedule and native guard before T-9.
    pub fn begin<'s, 'c, 'a, 't>(
        &'s mut self,
        c: &'c MiddleContext<'a>,
        schedule: &'t Im3Schedule,
        guard: &'t mut Im3Guard,
    ) -> Result<Im3RoundAttempt<'s, 'c, 'a, 't, P>> {
        guard.check(schedule)?;
        before(schedule.at(-9_000_000_000)?)?;
        if schedule.round() != c.r2.round.manifest.round()
            || self.store.binding() != c.profile.claim_binding(ClaimRole::Im3Sequence)
        {
            return Err(Error::Invalid("IM3 sequence context"));
        }
        let claim = self
            .store
            .consume(schedule.round(), c.r2.round.manifest.id(), c.q.id())
            .map_err(|_| Error::Unavailable("IM3 sequence round consumed/pending"))?;
        guard.check(schedule)?;
        before(schedule.at(-9_000_000_000)?)?;
        Ok(Im3RoundAttempt {
            claim,
            c,
            schedule,
            guard,
        })
    }
}

/// One non-cloneable round. Per-role owners should borrow `parts()`; Rust then
/// prevents terminal publication until they release the original guard.
/// Dropping this without a terminal publication leaves a durable pending
/// round: no hot retry, and cold reopen skips past it.
pub struct Im3RoundAttempt<'s, 'c, 'a, 't, P: ClaimPinRetention> {
    claim: ConsumedScope<'s, P>,
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t mut Im3Guard,
}
impl<P: ClaimPinRetention> Im3RoundAttempt<'_, '_, '_, '_, P> {
    /// The sole context/mapping/lease for constructing this round's owners.
    pub fn parts(&self) -> (&MiddleContext<'_>, &Im3Schedule, &Im3Guard) {
        (self.c, self.schedule, self.guard)
    }
    /// Publish terminal local abort only after all per-role owners are dropped
    /// and their links quarantined. The marker carries no error/source index.
    pub fn abort(mut self) -> Result<()> {
        let terminal = terminal(self.c, 1, &[0; 32]);
        self.claim
            .finish_im3_sequence(terminal)
            .map_err(|_| Error::Unavailable("IM3 sequence abort pin"))
    }
    /// B's completed original release/cleanup receipt, not settlement or
    /// producer delivery, allows the next round after all old owners drop.
    pub fn finish_release(mut self, completed: CompletedExit) -> Result<()> {
        if !completed.matches(self.c) {
            return Err(Error::Invalid("IM3 foreign completed B release"));
        }
        let terminal = terminal(self.c, 2, &completed.release_id);
        self.claim
            .finish_im3_sequence(terminal)
            .map_err(|_| Error::Unavailable("IM3 sequence release pin"))
    }
}
fn terminal(c: &MiddleContext<'_>, kind: u8, release: &Digest) -> Digest {
    domain_hash(
        "SilkNode-IM3-sequence-terminal",
        &[
            &[kind],
            &c.r2.round.config.id(),
            &c.profile.id(),
            &c.q.id(),
            &c.r2.round.manifest.id(),
            &c.r2.round.manifest.round().to_le_bytes(),
            release,
        ],
    )
}
