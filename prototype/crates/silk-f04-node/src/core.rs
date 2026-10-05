//! Serialized node coordinator. The durable adapter publishes its prepared changes.
// Keep this adapter explicitly crate-private even inside the private core.
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod order;
use crate::{
    Digest, Error, Result,
    budget::{AdmissionPhase, JobBudget, LocalClock},
    capacity::HistoryCapacityV1,
    carriage::{Body, Candidate, Header, MiningTemplate, ParentFacts, WorkEngine},
    genesis::Genesis,
    graph::{CryptoCache, DurableGraph as Graph, PreparedVertex},
    parent::PrefixCache,
    quantum::{Job, Progress},
    state::{BranchState, EffectOutcome},
};
use order::CoreOrder;
use silk_order::sg0_v1::{Sg0OrderSnapshotV1, Sg0ParentSetV1};
use silk_sapling_f04::parameters::SaplingParameters;
use silk_types::VertexId;
use std::{collections::VecDeque, sync::Arc};

/// Local processing status, not a consensus verdict about the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Complete state agrees with every completed interval of the admitted graph.
    Ready,
    /// Ordinary reconciliation of at most four prior checkpoints is pending.
    NeedsReconcile,
    /// Deeper preferred history needs bounded replay; serving/mining remains paused.
    ArchiveReplay,
}
impl Status {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::NeedsReconcile => 1,
            Self::ArchiveReplay => 2,
        }
    }
}

pub(crate) struct Core {
    pub genesis: Arc<Genesis>,
    pub graph: Graph,
    pub state: Arc<BranchState>,
    pub order: CoreOrder,
    pub clock: LocalClock,
    pub status: Status,
    prefixes: Option<PrefixCache>,
    active_admission: bool,
    crypto: CryptoCache,
    work: WorkEngine,
    history: VecDeque<Arc<BranchState>>,
    limits: crate::capacity::HistoryLimitsV1,
}
pub(crate) struct Admission {
    pub vertex: PreparedVertex,
    pub order: Sg0OrderSnapshotV1,
    pub retained_order: Option<CoreOrder>,
    pub status: Status,
    pub budget: JobBudget,
}
type ParentResult = (Result<ParentFacts>, PrefixCache);
enum Phase {
    Parent(Job<ParentResult>, Candidate),
    Body(Candidate, ParentFacts, JobBudget),
    Order(Job<(PreparedVertex, Sg0OrderSnapshotV1)>),
    Finished,
}
/// Live opaque continuation, never decoded from a peer or saved validity flag.
pub(crate) struct AdmissionJob {
    phase: Phase,
    domain: Digest,
    revision: usize,
}
pub(crate) struct Step {
    pub state: Arc<BranchState>,
    pub status: Status,
    pub outcomes: Vec<EffectOutcome>,
    pub rollback: bool,
    pub previous: Digest,
}

impl Core {
    #[cfg(test)]
    pub(crate) fn retained_history_for_test(&self) -> impl Iterator<Item = &Arc<BranchState>> {
        self.history.iter()
    }
    pub fn new(genesis: Arc<Genesis>, clock: LocalClock) -> Result<Self> {
        Self::new_with_limits(genesis, clock, crate::capacity::HistoryLimitsV1::REFERENCE)
    }
    pub(crate) fn new_with_limits(
        genesis: Arc<Genesis>,
        clock: LocalClock,
        limits: crate::capacity::HistoryLimitsV1,
    ) -> Result<Self> {
        limits.linear_generations()?;
        let graph = Graph::with_limits(limits);
        let state = Arc::new(BranchState::genesis_with_limits(&genesis, limits)?);
        let order = graph.order(&JobBudget::checkpoint()?)?;
        let prefixes = PrefixCache::new_with_limits(&genesis, limits)?;
        Ok(Self {
            genesis,
            graph,
            state,
            order: CoreOrder::resident(order),
            clock,
            status: Status::Ready,
            prefixes: Some(prefixes),
            active_admission: false,
            crypto: CryptoCache::default(),
            work: WorkEngine::default(),
            history: VecDeque::new(),
            limits,
        })
    }
    pub fn prepare(
        &mut self,
        bytes: &[u8],
        parameters: &SaplingParameters,
        retained: bool,
        budget: JobBudget,
    ) -> Result<Admission> {
        let mut job = self.begin_prepare(bytes, retained, budget)?;
        loop {
            if let Some(admission) = self.advance_prepare(&mut job, parameters)? {
                return Ok(admission);
            }
        }
    }
    fn start_parent(
        &mut self,
        parents: Sg0ParentSetV1,
        budget: JobBudget,
    ) -> Result<Job<ParentResult>> {
        let mut prefixes = self
            .prefixes
            .take()
            .ok_or(Error::Paused("parent job already owns cache"))?;
        let graph = self.graph.clone();
        let genesis = self.genesis.clone();
        budget.phase(AdmissionPhase::ParentOrder);
        Job::start(budget, move |budget| {
            let result = prefixes.derive(&graph, &parents, &genesis, budget);
            Ok((result, prefixes))
        })
    }
    pub fn begin_prepare(
        &mut self,
        bytes: &[u8],
        retained: bool,
        budget: JobBudget,
    ) -> Result<AdmissionJob> {
        if self.status != Status::Ready || self.active_admission {
            return Err(Error::Paused("reconcile before new admission"));
        }
        budget.phase(AdmissionPhase::CoreDecode);
        budget.check()?;
        let candidate = self.graph.decode_candidate(
            bytes,
            &self.genesis,
            if retained { None } else { Some(&self.clock) },
            &budget,
        )?;
        let worker = self.start_parent(candidate.header.parents.clone(), budget)?;
        self.active_admission = true;
        Ok(AdmissionJob {
            phase: Phase::Parent(worker, candidate),
            domain: self.genesis.domain(),
            revision: self.graph.len(),
        })
    }
    pub fn advance_prepare(
        &mut self,
        job: &mut AdmissionJob,
        parameters: &SaplingParameters,
    ) -> Result<Option<Admission>> {
        if !self.active_admission
            || job.domain != self.genesis.domain()
            || job.revision != self.graph.len()
        {
            return Err(Error::Unavailable("stale admission continuation"));
        }
        match std::mem::replace(&mut job.phase, Phase::Finished) {
            Phase::Parent(mut worker, candidate) => match worker.advance()? {
                Progress::Pending(usage) => {
                    debug_assert!(crate::quantum::Usage::default().permits(usage));
                    job.phase = Phase::Parent(worker, candidate);
                }
                Progress::Complete(result, budget) => {
                    let (facts, prefixes) = result?;
                    self.prefixes = Some(prefixes);
                    budget.check()?;
                    job.phase = Phase::Body(candidate, facts?, budget);
                }
            },
            Phase::Body(candidate, facts, budget) => {
                budget.phase(AdmissionPhase::BodyStart);
                budget.check()?;
                // Parent worker is joined before this sole exact work/crypto job.
                let verified = self.graph.verify_body(
                    candidate,
                    facts,
                    &self.genesis,
                    parameters,
                    &mut self.work,
                    &self.crypto,
                    &budget,
                );
                budget.check()?;
                let vertex = verified?;
                let graph = self.graph.clone();
                budget.phase(AdmissionPhase::VertexMetadata);
                job.phase = Phase::Order(Job::start(budget, move |budget| {
                    let vertex = graph.seal(vertex, budget)?;
                    budget.phase(AdmissionPhase::GraphOrder);
                    let order = graph.order_with(&vertex, budget)?;
                    Ok((vertex, order))
                })?);
            }
            Phase::Order(mut worker) => match worker.advance()? {
                Progress::Pending(usage) => {
                    debug_assert!(crate::quantum::Usage::default().permits(usage));
                    job.phase = Phase::Order(worker);
                }
                Progress::Complete(result, budget) => {
                    budget.check()?;
                    let (vertex, order) = result?;
                    budget.phase(AdmissionPhase::ReconciliationStatus);
                    let status = status_for(&self.state, order.eligible_order(), &budget)?;
                    budget.check()?;
                    for envelope in vertex.vertex().envelopes() {
                        self.crypto.insert(envelope.clone());
                    }
                    self.active_admission = false;
                    return Ok(Some(Admission {
                        vertex,
                        order,
                        retained_order: None,
                        status,
                        budget,
                    }));
                }
            },
            Phase::Finished => return Err(Error::Unavailable("finished admission continuation")),
        }
        Ok(None)
    }
    pub fn clear_rejected_admission(&mut self) -> Result<()> {
        if self.prefixes.is_none() {
            return Err(Error::Unavailable("failed derivation owns cache"));
        }
        self.active_admission = false;
        Ok(())
    }
    pub fn publish(&mut self, a: Admission) -> Result<JobBudget> {
        a.budget.phase(AdmissionPhase::CorePublication);
        a.budget.check()?;
        let retained_order = a
            .retained_order
            .ok_or(Error::Unavailable("durable order binding absent"))?;
        if !matches!(retained_order, CoreOrder::Retained(_)) {
            return Err(Error::Unavailable(
                "durable order must release resident snapshot",
            ));
        }
        if retained_order.bytes(&a.budget)? != order::snapshot_bytes(&a.order)
            || retained_order.selected_tip() != a.order.selected_tip()
        {
            return Err(Error::Unavailable("staged order publication mismatch"));
        }
        a.budget.check()?;
        self.graph.publish_checked(a.vertex, &a.budget)?;
        self.order = retained_order;
        self.status = a.status;
        Ok(a.budget)
    }
    pub fn prepare_step(&mut self, budget: &JobBudget) -> Result<Step> {
        if self.status == Status::Ready {
            return Err(Error::Unavailable("no reconciliation pending"));
        }
        budget.check()?;
        let old_len = self.state.executed_len();
        let inspection = self
            .order
            .inspect(&[self.state.as_ref()], Some(old_len), budget)?;
        let common = inspection.common[0];
        if common < old_len {
            let end = common / 8 * 8;
            let mut selected: Option<Arc<BranchState>> = None;
            let candidates = self
                .history
                .iter()
                .filter(|state| state.executed_len() <= end)
                .collect::<Vec<_>>();
            let states = candidates
                .iter()
                .copied()
                .map(Arc::as_ref)
                .collect::<Vec<_>>();
            let rollback = self.order.inspect(&states, None, budget)?;
            for (state, common) in candidates.iter().zip(&rollback.common) {
                if state.executed_len() <= end
                    && *common == state.executed_len()
                    && selected
                        .as_ref()
                        .is_none_or(|selected| state.executed_len() >= selected.executed_len())
                {
                    selected = Some((*state).clone());
                }
            }
            let state = selected.unwrap_or(Arc::new(BranchState::genesis_with_limits(
                &self.genesis,
                self.limits,
            )?));
            // A cached reversible snapshot is not permission to publish a
            // rollback whose original ledger pages are now unreadable.
            state.qualify_ledger_checked(budget)?;
            let derived_status =
                status_from_prefix(state.executed_len(), state.executed_len(), inspection.count);
            let status = if derived_status == Status::Ready {
                Status::Ready
            } else if self.status == Status::ArchiveReplay {
                Status::ArchiveReplay
            } else {
                derived_status
            };
            budget.check()?;
            return Ok(Step {
                state,
                status,
                outcomes: Vec::new(),
                rollback: true,
                previous: self.state.checkpoint_id(),
            });
        }
        let batch: &[VertexId; 8] = inspection
            .interval
            .as_slice()
            .try_into()
            .map_err(|_| Error::Unavailable("incomplete replay interval"))?;
        let verified = batch
            .iter()
            .map(|id| self.graph.load_for_execution(*id, &self.genesis, budget))
            .collect::<Result<Vec<_>>>()?;
        let t = self.state.execute(
            verified
                .iter()
                .map(Arc::as_ref)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| Error::Unavailable("checkpoint shape"))?,
            budget,
        )?;
        budget.check()?;
        let state = Arc::new(t.state);
        let status =
            if status_from_prefix(state.executed_len(), state.executed_len(), inspection.count)
                == Status::Ready
            {
                Status::Ready
            } else {
                self.status
            };
        Ok(Step {
            state,
            status,
            outcomes: t.outcomes,
            rollback: false,
            previous: self.state.checkpoint_id(),
        })
    }
    /// Upper bound for finishing the current preferred history, without work or
    /// state mutation. A divergent prefix may require genesis rollback plus all
    /// complete intervals; reuse of retained checkpoints can only lower the cost.
    pub fn reconciliation_generations(&self, budget: &JobBudget) -> Result<u64> {
        let inspection = self.order.inspect(&[self.state.as_ref()], None, budget)?;
        HistoryCapacityV1::reconciliation_with_limits(
            self.limits,
            self.state.executed_len(),
            inspection.common[0],
            inspection.count,
        )
    }
    pub fn publish_step(&mut self, s: Step) -> Result<()> {
        if s.previous != self.state.checkpoint_id() {
            return Err(Error::Unavailable("stale checkpoint publication"));
        }
        self.history.push_back(self.state.clone());
        while self.history.len() > 5 {
            self.history.pop_front();
        }
        self.prefixes
            .as_mut()
            .ok_or(Error::Paused("derivation still active"))?
            .remember(s.state.clone());
        self.state = s.state;
        self.status = s.status;
        Ok(())
    }
    pub fn mine(
        &mut self,
        body: Body,
        owner: Digest,
        reward_nonce: Digest,
        parents: Sg0ParentSetV1,
        fixture_timestamp: Option<u64>,
        budget: JobBudget,
    ) -> Result<Candidate> {
        let (template, budget) = self.prepare_mining(
            body,
            owner,
            reward_nonce,
            parents,
            fixture_timestamp,
            budget,
        )?;
        budget.check()?;
        let result = self.work.mine(&template, &budget);
        budget.check()?;
        result
    }
    pub fn prepare_mining(
        &mut self,
        body: Body,
        owner: Digest,
        reward_nonce: Digest,
        parents: Sg0ParentSetV1,
        fixture_timestamp: Option<u64>,
        budget: JobBudget,
    ) -> Result<(MiningTemplate, JobBudget)> {
        if self.status != Status::Ready || self.active_admission {
            return Err(Error::Paused("mining during reconciliation"));
        }
        if let Some(timestamp) = fixture_timestamp {
            self.clock.check_new(timestamp)?;
        }
        let mut worker = self.start_parent(parents.clone(), budget)?;
        let (facts, budget) = loop {
            if let Progress::Complete(result, budget) = worker.advance()? {
                let (facts, prefixes) = result?;
                self.prefixes = Some(prefixes);
                budget.check()?;
                break (facts?, budget);
            }
        };
        let timestamp = match fixture_timestamp {
            Some(timestamp) => timestamp,
            None => self
                .clock
                .mining_time(crate::node::system_wall()?, facts.minimum_time)?,
        };
        let header = Header::new(
            &self.genesis,
            parents,
            &body,
            owner,
            reward_nonce,
            timestamp,
            &facts,
        )?;
        // Mining is separate from receiver admission. Finding work does not
        // publish graph credit; the ordinary receiver must verify it again.
        budget.check()?;
        let result = MiningTemplate::new(&header, body, self.genesis.clone(), &facts)?;
        budget.check()?;
        Ok((result, budget))
    }
    pub fn selected_parent(&self, budget: &JobBudget) -> Result<Sg0ParentSetV1> {
        // Default mining selection may not proceed on an unreadable order.
        self.order.inspect(&[], None, budget)?;
        Ok(self
            .order
            .selected_tip()
            .map_or(Sg0ParentSetV1::Anchor, |id| {
                Sg0ParentSetV1::Vertices(vec![id])
            }))
    }
}
fn status_for(state: &BranchState, ids: &[VertexId], budget: &JobBudget) -> Result<Status> {
    let common = state.common_executed_prefix_checked(ids, Some(budget))?;
    Ok(status_from_prefix(state.executed_len(), common, ids.len()))
}
const fn status_from_prefix(executed: usize, common: usize, eligible: usize) -> Status {
    if common == executed && eligible / 8 * 8 == executed {
        Status::Ready
    } else if executed.saturating_sub(common / 8 * 8) > 32 {
        Status::ArchiveReplay
    } else {
        Status::NeedsReconcile
    }
}
