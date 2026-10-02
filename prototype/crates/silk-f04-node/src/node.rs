//! Explicit F0.4 durable node API. No legacy default, network listener or wallet secret.
//! Full-range synchronization uses the same live receiver as direct ingress.
#[cfg(test)]
mod ancestry_tests;
#[cfg(test)]
mod export_tests;
mod replay;
use crate::{
    Digest, Error, Result,
    budget::{JobBudget, LocalClock},
    capacity::{GENERATION_LIMIT_V1, HistoryCapacityV1},
    carriage::{Body, Candidate, encode_parents},
    core::{Admission, AdmissionJob, Core, Status},
    deadline::NativeGuard,
    genesis::Genesis,
    state::BranchState,
    store::{JobStartError, Store},
    wire::{field, raw_hash, u32le, u64le},
};
use rand_core::{OsRng, RngCore};
use silk_order::sg0_v1::{Sg0OrderSnapshotV1, Sg0ParentSetV1};
use silk_sapling_f04::parameters::SaplingParameters;
use silk_types::VertexId;
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub use crate::core::Status as NodeStatus;

/// Outcome distinguishes previously admitted exact bytes from new graph credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// Exact complete bytes were already verified/admitted locally.
    AlreadyKnown,
    /// One opaque bounded job is pending; no partial validity/work is published.
    Pending,
    /// Complete graph evidence is durable; state status still requires inspection.
    Admitted,
}

/// Sole writer of a private F0.4 node store. Not `Send`: RandomX belongs to this thread.
pub struct Node {
    core: Core,
    store: Store,
    sequence: u64,
    faulted: bool,
    recovered_previous: bool,
    pending: Option<PendingAdmission>,
}
// Field order joins the worker before native timers are disarmed on every exit.
struct PendingAdmission {
    job: AdmissionJob,
    guard: NativeGuard,
    id: Digest,
}
impl Drop for Node {
    fn drop(&mut self) {
        // Join any parked worker before the store lock or coordinator is dropped.
        self.pending.take();
    }
}

impl Node {
    /// Create a new private store under the separately qualified runtime. `margin`
    /// names the host filesystem outside a preallocated task store filesystem.
    pub fn create(root: &Path, margin: &Path, genesis: Genesis) -> Result<Self> {
        let mut clock = LocalClock::default();
        clock.observe(system_wall()?)?;
        let mut core = Core::new(Arc::new(genesis), clock)?;
        let store = Store::create(root, margin)?;
        core.graph
            .attach_ancestry_reader(store.object_reader()?, core.genesis.domain())?;
        let mut node = Self {
            core,
            store,
            sequence: 0,
            faulted: false,
            recovered_previous: false,
            pending: None,
        };
        let data = genesis_material(&node.core.genesis);
        node.commit(
            0,
            &data,
            node.core.state.clone(),
            &order_bytes(&node.core.order),
            0,
            node.core.status,
        )?;
        Ok(node)
    }

    /// Reopen ONLY this operator's authenticated retained local store. A received
    /// archive is never opened through this path: import its full records through
    /// `ingest`, which enforces receiver-local time and fresh work/crypto checks.
    /// Every retained graph record is independently revalidated, not trusted from
    /// decoded metadata or a snapshot. Serving is unavailable until this returns.
    pub fn open_retained(
        root: &Path,
        margin: &Path,
        genesis: Genesis,
        parameters: &SaplingParameters,
    ) -> Result<Self> {
        Self::open_store(Store::open(root, margin)?, genesis, parameters, true)
    }
    /// Reopen against a head saved independently by the local operator after a
    /// prior verified session. Never obtain this pin from the directory being
    /// offered for reopening. A mismatch/missing head refuses before recovery;
    /// external archive import must still use ordinary live `ingest`.
    pub fn open_retained_pinned(
        root: &Path,
        margin: &Path,
        genesis: Genesis,
        parameters: &SaplingParameters,
        expected_local_head: Digest,
    ) -> Result<Self> {
        Self::open_store(
            Store::open_pinned(root, margin, expected_local_head)?,
            genesis,
            parameters,
            false,
        )
    }
    fn open_store(
        mut store: Store,
        genesis: Genesis,
        parameters: &SaplingParameters,
        allow_previous_recovery: bool,
    ) -> Result<Self> {
        if store.active_replay()?.is_some() {
            return Err(Error::Paused(
                "interrupted retained replay requires explicit bounded authority",
            ));
        }
        // A cheap intact-header context check must not burn a replay attempt for
        // a caller's wrong public configuration. Corrupt-head recovery remains
        // possible only through the existing verified-previous path below.
        let current_record = store
            .head()
            .map(|id| store.object(id).and_then(|b| Record::decode(&b)))
            .transpose();
        if let Ok(Some(record)) = &current_record {
            if record.domain != genesis.domain() {
                return Err(Error::Unavailable("retained generation context"));
            }
        }
        // Only a plausible immediate completed transition may justify replay to
        // close a foreground marker. Missing/corrupt HEAD never suffices, even
        // when PREVIOUS happens to be the incomplete attempt's base.
        if let Some((_, marker)) = store.active_job()? {
            if !matches!(marker.get(..8), Some(b"SNF04JB1" | b"SNF04CJ1")) {
                return Err(Error::Paused(
                    "interrupted local job requires explicit bounded authority",
                ));
            }
            if marker.len() < 96 || marker[8..40] != genesis.domain() {
                return Err(Error::Unavailable("interrupted local job marker"));
            }
            let plausible = match &current_record {
                Ok(Some(record)) => marker_terminal_shape(&marker, record)?,
                _ => false,
            };
            if !plausible {
                return Err(Error::Paused(
                    "uncommitted local job requires explicit bounded authority",
                ));
            }
        }
        let mut replay_marker = Vec::from(b"SNF04RJ1".as_slice());
        replay_marker.extend_from_slice(&genesis.domain());
        replay_marker.extend_from_slice(&store.head().unwrap_or([0; 32]));
        let mut replay_nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut replay_nonce)
            .map_err(|_| Error::Unavailable("replay attempt entropy"))?;
        replay_marker.extend_from_slice(&replay_nonce);
        let replay_job = store.begin_replay(&replay_marker)?;
        let genesis = Arc::new(genesis);
        let attempted = match store.head() {
            Some(head) => Self::replay(&mut store, head, genesis.clone(), parameters),
            None => Err(Error::Unavailable("no complete local head")),
        };
        let (core, sequence, recovered_previous) = match attempted {
            Ok((core, sequence)) => (core, sequence, false),
            Err(e) if allow_previous_recovery && storage_integrity_failure(&e) => {
                let previous = store.previous()?.ok_or(e)?;
                let (core, sequence) = Self::replay(&mut store, previous, genesis, parameters)?;
                // No restoration until the previous COMPLETE generation has
                // passed fresh work, crypto, ordering and ledger replay.
                store.restore_verified(previous)?;
                (core, sequence, true)
            }
            Err(e) => return Err(e),
        };
        // A committed vertex can close a marker left by a crash after the head
        // switch. Otherwise loss of its stack/budget is a local STOP, not a retry.
        if let Some((job, bytes)) = store.active_job()? {
            if bytes.len() < 96 || bytes[8..40] != core.genesis.domain() {
                return Err(Error::Unavailable("interrupted local job marker"));
            }
            let terminal_head = store
                .head()
                .ok_or(Error::Unavailable("missing interrupted job head"))?;
            let terminal = Record::decode(&store.object(terminal_head)?)?;
            let count = u64le(&bytes, 72)?;
            let completed = match &bytes[..8] {
                b"SNF04JB1" => {
                    if bytes.len() < 100 || u32le(&bytes, 96)? as usize != bytes.len() - 100 {
                        return Err(Error::Unavailable("interrupted admission marker"));
                    }
                    let candidate = Candidate::decode(&bytes[100..], &core.genesis)?;
                    terminal.kind == 1
                        && Some(terminal.vertices) == count.checked_add(1)
                        && core
                            .graph
                            .get(VertexId::from_bytes(candidate.id))
                            .is_ok_and(|v| {
                                v.source_id().is_ok_and(|source| source == terminal.data)
                                    && core
                                        .graph
                                        .retained_candidate_matches(
                                            VertexId::from_bytes(candidate.id),
                                            &bytes[100..],
                                        )
                                        .is_ok_and(|same| same)
                            })
                }
                b"SNF04CJ1" => {
                    bytes.len() == 96
                        && matches!(terminal.kind, 2 | 3)
                        && terminal.vertices == count
                }
                _ => false,
            };
            // Full replay already checked the exact delta, checkpoint, order and
            // previous generation. Only THAT immediate transition may close this
            // marker; presence of a later checkpoint is never sufficient.
            if completed
                && terminal.previous == field::<32>(&bytes, 40)?
                && terminal.vertices == core.graph.len() as u64
            {
                store.finish_job(job, true)?;
            } else {
                return Err(Error::Paused(
                    "interrupted local transition requires explicit bounded authority",
                ));
            }
        }
        store.finish_replay(replay_job)?;
        Ok(Self {
            core,
            store,
            sequence,
            faulted: false,
            recovered_previous,
            pending: None,
        })
    }

    fn replay(
        store: &mut Store,
        head: Digest,
        genesis: Arc<Genesis>,
        parameters: &SaplingParameters,
    ) -> Result<(Core, u64)> {
        // The index contains only authenticated record addresses, never saved
        // validity or a decoded branch snapshot. Full semantic replay below is
        // unchanged; at most one fixed-size page is resident during traversal.
        let mut records = replay::ReplayPagesV1::build(store, head, genesis.domain())?;
        let mut core = Core::new(genesis, LocalClock::default())?;
        core.graph
            .attach_ancestry_reader(store.object_reader()?, core.genesis.domain())?;
        let mut previous = [0; 32];
        let mut last_sequence = 0;
        let mut index = 0_u64;
        while let Some(r) = records.next(store)? {
            // ACTIVE_REPLAY already durably fences this complete reopen. Each
            // record retains one original allowance through generation checks.
            // Outer traversal/initialization remains under the runtime's cap.
            let budget = if r.kind == 1 {
                JobBudget::vertex()?
            } else {
                JobBudget::checkpoint()?
            };
            let mut guard = NativeGuard::arm(&budget)?;
            if r.sequence != index || r.previous != previous {
                return Err(Error::Unavailable("generation lineage"));
            }
            if r.clock < core.clock.high_water() {
                return Err(Error::Unavailable("retained clock rollback"));
            }
            core.clock.observe(r.clock)?;
            let data = store.object(r.data)?;
            let budget = match r.kind {
                0 if index == 0 => {
                    if data != genesis_material(&core.genesis) {
                        return Err(Error::Unavailable("accepted genesis material changed"));
                    }
                    budget
                }
                1 if index > 0 => {
                    let len = u32le(&data, 8)? as usize;
                    if data.len() < 12
                        || &data[..8] != b"SNF04VR1"
                        || !(720..=90_000).contains(&len)
                        || data.len() < 12 + len + 184 + 4
                    {
                        return Err(Error::Unavailable("retained vertex framing"));
                    }
                    let mut a = core.prepare(&data[12..12 + len], parameters, true, budget)?;
                    if a.vertex.vertex().retained_record()? != data {
                        return Err(Error::Unavailable("retained source/SG0 metadata mismatch"));
                    }
                    a.vertex.retain_ancestry(&core.graph, store, &a.budget)?;
                    a.vertex.bind_retained_source(&data)?;
                    core.publish(a)?
                }
                2 | 3 if index > 0 => {
                    let s = core.prepare_step(&budget)?;
                    if (r.kind == 3) != s.rollback
                        || s.state.delta(&core.state, &s.outcomes, s.rollback)? != data
                    {
                        return Err(Error::Unavailable("retained reversible delta mismatch"));
                    }
                    core.publish_step(s)?;
                    budget
                }
                4 if index > 0 => {
                    if !data.is_empty() {
                        return Err(Error::Unavailable("local metadata record"));
                    }
                    budget
                }
                _ => return Err(Error::Unavailable("generation transition kind")),
            };
            if core.status.byte() != r.status
                || core.graph.len() as u64 != r.vertices
                || core.state.checkpoint_id() != r.checkpoint
                || store.object(r.state)? != core.state.manifest()
                || store.object(r.order)? != order_bytes(&core.order)
            {
                return Err(Error::Unavailable("complete generation mismatch"));
            }
            previous = raw_hash(&r.encode());
            last_sequence = r.sequence;
            budget.check()?;
            guard.finish();
            index += 1;
        }
        if previous != head {
            return Err(Error::Unavailable("terminal head mismatch"));
        }
        core.clock.observe(system_wall()?)?;
        Ok((core, last_sequence + 1))
    }

    /// Explicit recovery report. Damaged head evidence is retained in quarantine.
    #[must_use]
    pub const fn recovered_previous(&self) -> bool {
        self.recovered_previous
    }

    /// Current local phase. A faulted writer must be cold-reopened and revalidated.
    pub fn status(&self) -> Result<NodeStatus> {
        self.healthy()?;
        self.idle()?;
        Ok(self.core.status)
    }
    /// Only a complete reconciled ledger is exposed as current.
    pub fn state(&self) -> Result<&BranchState> {
        self.healthy()?;
        self.idle()?;
        if self.core.status != Status::Ready {
            return Err(Error::Paused("state reconciliation incomplete"));
        }
        Ok(&self.core.state)
    }
    /// Exact public genesis context, never spending/viewing material.
    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.core.genesis
    }
    /// Retained full-data graph count, including red evidence.
    #[must_use]
    pub fn vertex_count(&self) -> usize {
        self.core.graph.len()
    }
    /// Conservative persistent accounting includes unreachable and staged files.
    #[must_use]
    pub fn accounted_bytes(&self) -> u64 {
        self.store.accounted_bytes()
    }
    /// Local reference-horizon bounds for participation/resource controls. This
    /// is read-only derived metadata, not a disk reservation or admission permit.
    /// # Errors
    /// Refuses a faulted writer or pending admission continuation.
    pub fn history_capacity(&self) -> Result<HistoryCapacityV1> {
        self.healthy()?;
        self.idle()?;
        HistoryCapacityV1::for_counts(
            self.sequence,
            self.core.graph.len(),
            self.core.state.executed_len(),
        )
    }
    /// Reserve a bounded public output against the same whole-task store/margin
    /// policy. The runtime must place the actual output on that capped volume.
    pub fn check_public_output_capacity(&self, bytes: usize) -> Result<()> {
        self.healthy()?;
        self.idle()?;
        if bytes > crate::carriage::MAX_VERTEX_BYTES {
            return Err(Error::Paused("public output bound"));
        }
        self.store.check_external_write(bytes)
    }
    /// Local lineage identity to retain outside received archive/configuration
    /// inputs. This is not a peer's consensus checkpoint or an acceptance receipt.
    pub fn local_head(&self) -> Result<Digest> {
        self.healthy()?;
        self.idle()?;
        self.store
            .head()
            .ok_or(Error::Unavailable("missing local head"))
    }

    /// Direct ingress AND sync use this one live admission route. No caller can
    /// assert that a newly received record is historical or already verified.
    pub fn ingest(&mut self, bytes: &[u8], parameters: &SaplingParameters) -> Result<Ingress> {
        let mut result = self.begin_ingest(bytes)?;
        while result == Ingress::Pending {
            result = self.resume_ingest(parameters)?;
        }
        Ok(result)
    }
    /// Start one live admission without granting its worker a quantum yet.
    /// The durable incomplete marker prevents a restart from renewing its cap.
    pub fn begin_ingest(&mut self, bytes: &[u8]) -> Result<Ingress> {
        self.healthy()?;
        self.idle()?;
        let budget = JobBudget::vertex()?;
        self.core.clock.observe(system_wall()?)?;
        let c = Candidate::decode(bytes, &self.core.genesis)?;
        if let Ok(v) = self.core.graph.get(VertexId::from_bytes(c.id)) {
            if self
                .core
                .graph
                .retained_candidate_matches(VertexId::from_bytes(v.id()), bytes)?
            {
                return Ok(Ingress::AlreadyKnown);
            }
            return Err(Error::Invalid(
                "existing vertex ID with different full bytes",
            ));
        }
        if self.core.status != Status::Ready {
            return Err(Error::Paused("reconcile before new admission"));
        }
        self.core.clock.check_new(c.header.timestamp)?;
        for parent in c.header.parents.ordinary_parents() {
            self.core.graph.get(*parent)?;
        }
        // Do not create an interrupted-attempt fence or start native work for
        // an admission that cannot fit its eventual complete reconciliation.
        self.history_capacity()?.check_admission()?;
        let mut marker = Vec::with_capacity(100 + bytes.len());
        marker.extend_from_slice(b"SNF04JB1");
        marker.extend_from_slice(&self.core.genesis.domain());
        marker.extend_from_slice(
            &self
                .store
                .head()
                .ok_or(Error::Unavailable("missing admission base head"))?,
        );
        marker.extend_from_slice(&(self.core.graph.len() as u64).to_le_bytes());
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("admission nonce entropy"))?;
        marker.extend_from_slice(&nonce);
        marker.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        marker.extend_from_slice(bytes);
        let job_id = self.begin_foreground_job(&marker)?;
        let guard = match NativeGuard::arm(&budget) {
            Ok(guard) => guard,
            Err(e) => return self.job_failed(job_id, e),
        };
        match self.core.begin_prepare(bytes, false, budget) {
            Ok(job) => {
                self.pending = Some(PendingAdmission {
                    job,
                    guard,
                    id: job_id,
                });
                Ok(Ingress::Pending)
            }
            Err(e) => self.job_failed(job_id, e),
        }
    }
    /// Advance one derivation/validation phase. Ordinary yielding counts against
    /// the ORIGINAL per-vertex time allowance; do not insert scheduling sleeps.
    pub fn resume_ingest(&mut self, parameters: &SaplingParameters) -> Result<Ingress> {
        self.healthy()?;
        let mut pending = self
            .pending
            .take()
            .ok_or(Error::Unavailable("no pending admission"))?;
        match self.core.advance_prepare(&mut pending.job, parameters) {
            Ok(None) => {
                self.pending = Some(pending);
                Ok(Ingress::Pending)
            }
            Ok(Some(admission)) => {
                let result = (|| {
                    let budget = self.publish_admission(admission)?;
                    budget.check()?;
                    self.store.finish_job(pending.id, true)
                })();
                if let Err(e) = result {
                    self.faulted = true;
                    return Err(e);
                }
                pending.guard.finish();
                Ok(Ingress::Admitted)
            }
            Err(e) => self.job_failed(pending.id, e),
        }
    }
    fn job_failed<T>(&mut self, job_id: Digest, error: Error) -> Result<T> {
        // Only definite protocol failure closes a failed attempt for continued
        // service. Any unknown/resource/I/O failure keeps its restart-stop marker.
        if matches!(
            &error,
            Error::Invalid(_)
                | Error::Sapling(
                    silk_sapling_f04::Error::Encoding(_) | silk_sapling_f04::Error::Crypto(_)
                )
        ) {
            if let Err(e) = self
                .core
                .clear_rejected_admission()
                .and_then(|()| self.store.finish_job(job_id, false))
            {
                self.faulted = true;
                return Err(e);
            }
        } else {
            self.faulted = true;
        }
        Err(error)
    }
    fn publish_admission(&mut self, mut a: Admission) -> Result<JobBudget> {
        a.budget.check()?;
        let data = a.vertex.vertex().retained_record()?;
        let order = order_bytes(&a.order);
        self.commit(
            1,
            &data,
            self.core.state.clone(),
            &order,
            self.core.graph.len() as u64 + 1,
            a.status,
        )?;
        if let Err(error) = (|| {
            a.vertex
                .retain_ancestry(&self.core.graph, &mut self.store, &a.budget)?;
            a.vertex.bind_retained_source(&data)
        })() {
            self.faulted = true;
            return Err(error);
        }
        match self.core.publish(a) {
            Ok(budget) => Ok(budget),
            Err(e) => {
                self.faulted = true;
                Err(e)
            }
        }
    }
    /// One reversible checkpoint (or whole-state rollback) per call. No automatic
    /// admission/mining while archive replay is incomplete; never unions NF/cuts.
    pub fn advance(&mut self) -> Result<NodeStatus> {
        self.healthy()?;
        self.idle()?;
        if self.core.status == Status::Ready {
            return Ok(Status::Ready);
        }
        self.history_capacity()?
            .check_generations(self.core.reconciliation_generations()?)?;
        let budget = JobBudget::checkpoint()?;
        let mut marker = Vec::from(b"SNF04CJ1".as_slice());
        marker.extend_from_slice(&self.core.genesis.domain());
        marker.extend_from_slice(&self.local_head()?);
        marker.extend_from_slice(&(self.core.graph.len() as u64).to_le_bytes());
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("checkpoint attempt entropy"))?;
        marker.extend_from_slice(&nonce);
        let job_id = self.begin_foreground_job(&marker)?;
        let result = (|| {
            let mut guard = NativeGuard::arm(&budget)?;
            let step = self.core.prepare_step(&budget)?;
            let data = step
                .state
                .delta(&self.core.state, &step.outcomes, step.rollback)?;
            budget.check()?;
            self.commit(
                if step.rollback { 3 } else { 2 },
                &data,
                step.state.clone(),
                &order_bytes(&self.core.order),
                self.core.graph.len() as u64,
                step.status,
            )?;
            self.core.publish_step(step)?;
            budget.check()?;
            // Final cooperative decision precedes terminal closure. A completed
            // closure must not then be relabeled an unfinished budget failure.
            // On Linux the original native lease also spans terminal I/O; on
            // other platforms this remains only a cooperative decision.
            self.store.finish_job(job_id, true)?;
            guard.finish();
            Ok(self.core.status)
        })();
        if result.is_err() {
            self.faulted = true;
        }
        result
    }
    /// Persist the nondecreasing local wall observation before a clean shutdown.
    pub fn flush_clock(&mut self) -> Result<()> {
        self.healthy()?;
        self.idle()?;
        // Clock-only publication must not consume the slots needed to finish
        // an already admitted preferred-history transition.
        self.history_capacity()?
            .check_generations(1 + self.core.reconciliation_generations()?)?;
        self.core.clock.observe(system_wall()?)?;
        self.commit(
            4,
            &[],
            self.core.state.clone(),
            &order_bytes(&self.core.order),
            self.core.graph.len() as u64,
            self.core.status,
        )?;
        Ok(())
    }
    /// Build genuine work in this explicit private local experiment. This is not
    /// a public raw-envelope endpoint or a bypass around the required relay policy.
    /// A result still needs the ordinary `ingest` receiver and durable publication.
    pub fn mine_candidate(
        &mut self,
        body: Body,
        owner: Digest,
        reward_nonce: Digest,
        parents: Option<Sg0ParentSetV1>,
        timestamp: u64,
    ) -> Result<Candidate> {
        self.mine_inner(body, owner, reward_nonce, parents, Some(timestamp))
    }
    /// Ordinary local mining timestamp policy: freshly observed wall or checked
    /// parent/MTP minimum, whichever is later. No user-selected historical time.
    /// This is not a wallet submission route or an implicit relay bypass.
    pub fn mine_current(
        &mut self,
        body: Body,
        owner: Digest,
        reward_nonce: Digest,
        parents: Option<Sg0ParentSetV1>,
    ) -> Result<Candidate> {
        self.mine_inner(body, owner, reward_nonce, parents, None)
    }
    fn mine_inner(
        &mut self,
        body: Body,
        owner: Digest,
        reward_nonce: Digest,
        parents: Option<Sg0ParentSetV1>,
        fixture_timestamp: Option<u64>,
    ) -> Result<Candidate> {
        self.healthy()?;
        self.idle()?;
        if self.core.status != Status::Ready {
            return Err(Error::Paused("mining during reconciliation"));
        }
        self.history_capacity()?.check_admission()?;
        let budget = JobBudget::vertex()?;
        self.core.clock.observe(system_wall()?)?;
        if let Some(timestamp) = fixture_timestamp {
            self.core.clock.check_new(timestamp)?;
        }
        let parents = parents.unwrap_or_else(|| self.core.selected_parent());
        let mut marker = Vec::new();
        marker.extend_from_slice(b"SNF04MJ1");
        marker.extend_from_slice(&self.core.genesis.domain());
        marker.extend_from_slice(&self.local_head()?);
        marker.extend_from_slice(&(self.core.graph.len() as u64).to_le_bytes());
        marker.extend_from_slice(&encode_parents(&parents)?);
        marker.extend_from_slice(&owner);
        marker.extend_from_slice(&reward_nonce);
        marker.push(u8::from(fixture_timestamp.is_some()));
        marker.extend_from_slice(&fixture_timestamp.unwrap_or(0).to_le_bytes());
        let mut attempt = [0; 16];
        OsRng
            .try_fill_bytes(&mut attempt)
            .map_err(|_| Error::Unavailable("mining attempt entropy"))?;
        marker.extend_from_slice(&attempt);
        marker.extend_from_slice(body.bytes());
        let job_id = self.begin_foreground_job(&marker)?;
        let mut guard = match NativeGuard::arm(&budget) {
            Ok(guard) => guard,
            Err(e) => return self.job_failed(job_id, e),
        };
        match self.core.mine(
            body,
            owner,
            reward_nonce,
            parents,
            fixture_timestamp,
            budget,
        ) {
            Ok(candidate) => {
                // Completed mining has NOT admitted a vertex. Only the ordinary
                // live receiver may subsequently grant graph credit.
                if let Err(e) = self.store.finish_job(job_id, false) {
                    self.faulted = true;
                    return Err(e);
                }
                guard.finish();
                Ok(candidate)
            }
            Err(e) => self.job_failed(job_id, e),
        }
    }
    /// Bounded public full-range evidence export, never wallet/note-specific lookup.
    /// Receivers ingest these bytes through their normal live admission route.
    pub fn export_range(&self, start: usize, count: usize) -> Result<Vec<Vec<u8>>> {
        self.healthy()?;
        self.core.graph.export_retained_range(start, count)
    }
    fn healthy(&self) -> Result<()> {
        if self.faulted {
            Err(Error::Unavailable(
                "writer stopped after publication failure",
            ))
        } else {
            Ok(())
        }
    }
    fn begin_foreground_job(&mut self, marker: &[u8]) -> Result<Digest> {
        match self.store.begin_job(marker) {
            Ok(id) => Ok(id),
            Err(JobStartError::Refused(error)) => Err(error),
            Err(JobStartError::Uncertain(error)) => {
                self.faulted = true;
                Err(error)
            }
        }
    }
    fn idle(&self) -> Result<()> {
        if self.pending.is_some() {
            Err(Error::Paused("admission continuation pending"))
        } else {
            Ok(())
        }
    }
    fn commit(
        &mut self,
        kind: u8,
        data: &[u8],
        state: Arc<BranchState>,
        order: &[u8],
        vertices: u64,
        status: Status,
    ) -> Result<Digest> {
        if self.sequence >= GENERATION_LIMIT_V1 {
            return Err(Error::Paused("generation reference horizon"));
        }
        let manifest = state.manifest();
        let r = Record {
            kind,
            status: status.byte(),
            sequence: self.sequence,
            previous: self.store.head().unwrap_or([0; 32]),
            domain: self.core.genesis.domain(),
            clock: self.core.clock.high_water(),
            data: raw_hash(data),
            state: raw_hash(&manifest),
            order: raw_hash(order),
            checkpoint: state.checkpoint_id(),
            vertices,
        };
        let result = self.store.commit(&[data, &manifest, order], &r.encode());
        match result {
            Ok(id) => {
                self.sequence += 1;
                Ok(id)
            }
            Err(e) => {
                self.faulted = true;
                Err(e)
            }
        }
    }
}

fn marker_terminal_shape(marker: &[u8], terminal: &Record) -> Result<bool> {
    if marker.len() < 96
        || marker[8..40] != terminal.domain
        || field::<32>(marker, 40)? != terminal.previous
    {
        return Ok(false);
    }
    let count = u64le(marker, 72)?;
    match &marker[..8] {
        b"SNF04CJ1" => {
            Ok(marker.len() == 96 && matches!(terminal.kind, 2 | 3) && terminal.vertices == count)
        }
        b"SNF04JB1" => Ok(marker.len() >= 100
            && u32le(marker, 96)? as usize == marker.len() - 100
            && terminal.kind == 1
            && Some(terminal.vertices) == count.checked_add(1)),
        _ => Ok(false),
    }
}

pub(crate) fn storage_integrity_failure(e: &Error) -> bool {
    match e {
        Error::Unavailable(
            "no complete local head"
            | "content object hash"
            | "store object type/length"
            | "changed store object"
            | "generation record encoding",
        ) => true,
        Error::Io(e) => matches!(
            e.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::InvalidData
        ),
        _ => false,
    }
}
pub(crate) fn system_wall() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| Error::Paused("untrusted system wall clock"))
}
fn genesis_material(g: &Genesis) -> Vec<u8> {
    g.local_bundle()
}
fn order_bytes(o: &Sg0OrderSnapshotV1) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"SNF04OR1");
    b.extend_from_slice(&o.graph_commitment().into_bytes());
    b.extend_from_slice(&o.total_order_commitment().into_bytes());
    b.extend_from_slice(&(o.eligible_order().len() as u32).to_le_bytes());
    for id in o.eligible_order() {
        b.extend_from_slice(&id.into_bytes());
    }
    b
}
struct Record {
    kind: u8,
    status: u8,
    sequence: u64,
    previous: Digest,
    domain: Digest,
    clock: u64,
    data: Digest,
    state: Digest,
    order: Digest,
    checkpoint: Digest,
    vertices: u64,
}
impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(232);
        b.extend_from_slice(b"SNF04HD1\x01\0\0\0");
        b.extend_from_slice(&[self.kind, self.status, 0, 0]);
        b.extend_from_slice(&self.sequence.to_le_bytes());
        b.extend_from_slice(&self.previous);
        b.extend_from_slice(&self.domain);
        b.extend_from_slice(&self.clock.to_le_bytes());
        for h in [&self.data, &self.state, &self.order, &self.checkpoint] {
            b.extend_from_slice(h);
        }
        b.extend_from_slice(&self.vertices.to_le_bytes());
        b
    }
    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 232
            || &b[..12] != b"SNF04HD1\x01\0\0\0"
            || b[12] > 4
            || b[13] > 2
            || b[14..16] != [0; 2]
        {
            return Err(Error::Unavailable("generation record encoding"));
        }
        Ok(Self {
            kind: b[12],
            status: b[13],
            sequence: u64le(b, 16)?,
            previous: field(b, 24)?,
            domain: field(b, 56)?,
            clock: u64le(b, 88)?,
            data: field(b, 96)?,
            state: field(b, 128)?,
            order: field(b, 160)?,
            checkpoint: field(b, 192)?,
            vertices: u64le(b, 224)?,
        })
    }
}
