//! One checkpoint reducer shared by canonical execution and parent-prefix replay.
//! A cut is a reversible prefix reference, never a finality certificate.
mod history;
mod recovery;
mod sequence;
mod sets;
use crate::economics::{
    CREDIT_MATURITY_V1, EconomicCountsV1, EconomicLedgerV1, PRIVATE_BURN_V1, PUBLIC_CREDIT_V1,
};
use crate::{Digest, Error, Result, genesis::Genesis, graph::VerifiedVertex, wire::raw_hash};
use history::LedgerHistory;
use recovery::RecoveryHistory;
use sapling_crypto::{CommitmentTree, Node};
use sets::PagedLedgerSet;
use sha2::{Digest as _, Sha256};
use silk_pow::randomx_v2_work_key_id;
use silk_sapling_f04::{
    codec::{RECOVERY_BYTES, domain_hash},
    crypto::VerifiedEnvelope,
    wallet::CutReference,
};
use silk_types::VertexId;
use std::{collections::VecDeque, sync::Arc};

/// Private immutable, operation-local ledger comparison, never persisted authority.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct ExecutionComparison<'a>(history::PrefixComparison<'a, VertexId>);
impl ExecutionComparison<'_> {
    pub(crate) fn advance(
        &mut self,
        id: &VertexId,
        budget: &crate::budget::JobBudget,
    ) -> Result<()> {
        self.0.advance(id, Some(budget))
    }
    pub(crate) fn finish(self, budget: &crate::budget::JobBudget) -> Result<usize> {
        self.0.finish(Some(budget))
    }
}

/// Canonical cut with its exact prefix and leaf-count lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    /// Cut ordinal, at checkpoint 128*c (zero is genesis).
    pub index: u64,
    /// Checkpoint-prefix commitment Q, not merely a note root.
    pub prefix: Digest,
    /// Standard Sapling tree root at that prefix.
    pub root: Digest,
    /// Number of positioned leaves present at the cut.
    pub leaves: u64,
    /// Exact Kc.
    pub id: Digest,
}
impl Cut {
    fn new(n: &Digest, index: u64, prefix: Digest, root: Digest, leaves: u64) -> Self {
        let id = domain_hash(
            "SilkNode-F0-cut",
            &[
                n,
                &index.to_le_bytes(),
                &prefix,
                &root,
                &leaves.to_le_bytes(),
            ],
        );
        Self {
            index,
            prefix,
            root,
            leaves,
            id,
        }
    }
    /// Wallet construction binding; availability/maturity is checked by the caller.
    #[must_use]
    pub fn reference(&self, domain: Digest) -> CutReference {
        CutReference {
            domain,
            index: self.index,
            id: self.id,
            root: self.root,
        }
    }
}

/// Deterministic effect result. All variants retain the carrier's work/public position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectOutcome {
    /// Both inputs/outputs and the one-unit burn applied together.
    Accepted,
    /// The exact signed cut is immature or absent on this canonical prefix.
    IneligibleCut,
    /// A previously accepted effect is a fee-free no-op.
    Duplicate,
    /// At least one input is already spent; neither new input is consumed.
    Conflict,
    /// Pool, integer or tree-capacity checks refused the whole effect.
    Bounds,
}

/// Derived linkage created ONLY when an effect applies atomically. Public bytes,
/// not a serialized consensus object, peer snapshot or outgoing-viewing capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedOutputs {
    /// Exact accepted economic effect, independent of authorization encoding.
    pub effect: Digest,
    /// Canonical position of output slot zero; slot one follows immediately.
    pub first_position: u64,
    /// Value commitments from those exact slots in the accepted envelope.
    pub commitments: [Digest; 2],
}

/// Derived immutable completed branch state. Mutation occurs only in the reducer.
#[derive(Clone)]
pub struct BranchState {
    domain: Digest,
    parameters: Digest,
    initial_leaves: u64,
    initial_pool: u64,
    tree: CommitmentTree,
    nullifiers: PagedLedgerSet,
    effects: PagedLedgerSet,
    // Share immutable entries across reversible states; do not copy ciphertext history.
    recovery: RecoveryHistory,
    // Derived only; NEVER added to current hashes, manifests, deltas or wire bytes.
    accepted_outputs: LedgerHistory<Arc<AcceptedOutputs>>,
    rewards: LedgerHistory<[u8; 112]>,
    pool: u64,
    burned: u64,
    issued: u128,
    executed: LedgerHistory<VertexId>,
    j: Digest,
    tail: VecDeque<[u8; 56]>,
    dc: Digest,
    kc: Digest,
    checkpoint_index: u64,
    checkpoint: Vec<u8>,
    checkpoint_id: Digest,
    state_digest: Digest,
    prefix: Digest,
    cuts: Vec<Cut>,
}

/// Reversible checkpoint result. Publication, not construction, makes it current.
pub(crate) struct CheckpointTransition {
    pub state: BranchState,
    pub outcomes: Vec<EffectOutcome>,
}

impl BranchState {
    /// Complete checkpoint-zero state from admitted immutable genesis material.
    pub fn genesis(g: &Genesis) -> Result<Self> {
        let domain = g.domain();
        let parameters = g.parameters_id();
        let j = domain_hash("SilkNode-F0-eligible-genesis", &[&domain]);
        let kc = domain_hash("SilkNode-F01-key-carry-genesis", &[&domain, &parameters]);
        // Same genesis plus two outputs per accepted-effect horizon. No received
        // page, saved validity or enlarged effect/scanner limit is introduced.
        let limit = g
            .recoveries()
            .len()
            .checked_add(100_000)
            .ok_or(Error::Paused("recovery sequence reference horizon"))?;
        let mut recovery = RecoveryHistory::new(limit);
        for entry in g.recoveries() {
            recovery.push(Arc::new(*entry))?;
        }
        let mut s = Self {
            domain,
            parameters,
            initial_leaves: g.recoveries().len() as u64,
            initial_pool: g.total(),
            tree: g.tree().clone(),
            nullifiers: PagedLedgerSet::new(100_000),
            effects: PagedLedgerSet::new(50_000),
            recovery,
            accepted_outputs: LedgerHistory::new(50_000),
            rewards: LedgerHistory::new(crate::sync::HISTORY_LIMIT_V1),
            pool: g.total(),
            burned: 0,
            issued: 0,
            executed: LedgerHistory::new(crate::sync::HISTORY_LIMIT_V1),
            j,
            tail: VecDeque::new(),
            dc: [0; 32],
            kc,
            checkpoint_index: 0,
            checkpoint: Vec::new(),
            checkpoint_id: [0; 32],
            state_digest: [0; 32],
            prefix: [0; 32],
            cuts: Vec::new(),
        };
        s.dc = s.daa_carry();
        s.state_digest = s.hash_state();
        s.checkpoint.extend_from_slice(b"SNCGEN01");
        for field in [&domain, &s.state_digest, &s.dc, &kc] {
            s.checkpoint.extend_from_slice(field);
        }
        s.checkpoint_id = domain_hash("SilkNode-F0-checkpoint-genesis", &[&s.checkpoint]);
        s.prefix = domain_hash("SilkNode-F0-prefix-genesis", &[&domain, &s.checkpoint_id]);
        s.cuts
            .push(Cut::new(&domain, 0, s.prefix, s.root(), s.leaves()));
        s.check_invariants()?;
        Ok(s)
    }

    /// Exactly eight fully admitted vertices at the next eligible checkpoint.
    /// The graph owner checks this batch against its SG-0 sequence; scratch callers
    /// use the candidate's parent sequence, not the unrelated current ledger.
    pub(crate) fn execute(
        &self,
        batch: [&VerifiedVertex; 8],
        budget: &crate::budget::JobBudget,
    ) -> Result<CheckpointTransition> {
        budget.check()?;
        // Clone live metadata only. Historical payloads stay retained; appends
        // and leaf edits remain private until complete hash/invariant checks.
        let mut next = self.prepare_ledger_mutation(budget)?;
        let j = self
            .checkpoint_index
            .checked_add(1)
            .ok_or(Error::Invalid("checkpoint overflow"))?;
        if self.executed.len() as u64 != self.checkpoint_index * 8 {
            return Err(Error::Unavailable("checkpoint cursor invariant"));
        }
        let mut outcomes = Vec::new();
        for v in batch {
            budget.check()?;
            if v.candidate().header.bytes[560..] != self.domain {
                return Err(Error::Unavailable("reducer foreign vertex"));
            }
            for e in v.envelopes() {
                budget.check()?;
                outcomes.push(next.execute_envelope(e, j, budget)?);
            }
            next.append_position(v)?;
        }
        next.checkpoint_index = j;
        next.dc = next.daa_carry();
        next.state_digest = next.hash_state_checked(Some(budget))?;
        let mut c = Vec::with_capacity(484);
        c.extend_from_slice(b"SNCPTF01\x01\0\0\0");
        c.extend_from_slice(&self.domain);
        c.extend_from_slice(&j.to_le_bytes());
        c.extend_from_slice(&self.checkpoint_id);
        c.extend_from_slice(&next.j);
        for v in batch {
            c.extend_from_slice(&v.candidate().id);
        }
        for h in [&next.state_digest, &next.dc, &next.kc] {
            c.extend_from_slice(h);
        }
        c.extend_from_slice(&(next.executed.len() as u64).to_le_bytes());
        c.extend_from_slice(&0_u64.to_le_bytes());
        debug_assert_eq!(c.len(), 484);
        next.checkpoint_id = domain_hash("SilkNode-F0-checkpoint", &[&c]);
        next.prefix = domain_hash(
            "SilkNode-F0-prefix",
            &[&self.domain, &self.prefix, &j.to_le_bytes(), &raw_hash(&c)],
        );
        next.checkpoint = c;
        if j % 128 == 0 {
            next.cuts.push(Cut::new(
                &self.domain,
                j / 128,
                next.prefix,
                next.root(),
                next.leaves(),
            ));
        }
        next.check_invariants_checked(Some(budget))?;
        budget.check()?;
        Ok(CheckpointTransition {
            state: next,
            outcomes,
        })
    }

    fn execute_envelope(
        &mut self,
        verified: &VerifiedEnvelope,
        j: u64,
        budget: &crate::budget::JobBudget,
    ) -> Result<EffectOutcome> {
        let e = verified.envelope();
        if e.domain() != self.domain {
            return Err(Error::Unavailable("reducer foreign envelope"));
        }
        let c = e.cut_index();
        let eligible = c <= eligible_cut_index(j)
            && self.cuts.get(c as usize).is_some_and(|cut| {
                cut.index == c && cut.id == e.cut_id() && cut.root == e.anchor()
            });
        if !eligible {
            return Ok(EffectOutcome::IneligibleCut);
        }
        let effect = e.effect_id();
        if self.effects.contains_checked(&effect, Some(budget))? {
            return Ok(EffectOutcome::Duplicate);
        }
        let nfs = e.nullifiers();
        for nf in &nfs {
            if self.nullifiers.contains_checked(nf, Some(budget))? {
                return Ok(EffectOutcome::Conflict);
            }
        }
        if self.effects.len() >= 50_000 {
            return Err(Error::Paused("accepted-effect reference horizon"));
        }
        let Some(next_pool) = self.pool.checked_sub(PRIVATE_BURN_V1) else {
            return Ok(EffectOutcome::Bounds);
        };
        let Some(next_burned) = self.burned.checked_add(PRIVATE_BURN_V1) else {
            return Ok(EffectOutcome::Bounds);
        };
        if self.leaves() > (1_u64 << 32) - 2 {
            return Ok(EffectOutcome::Bounds);
        }
        let entries = e.recovery();
        let linkage = AcceptedOutputs {
            effect,
            first_position: self.leaves(),
            commitments: e.output_value_commitments(),
        };
        // Stage the entire two-output tree update before any economic write.
        let mut tree = self.tree.clone();
        for entry in &entries {
            let node = Option::<Node>::from(Node::from_bytes(
                entry[..32].try_into().expect("fixed recovery"),
            ))
            .ok_or(Error::Unavailable("verified output commitment invariant"))?;
            tree.append(node)
                .map_err(|()| Error::Unavailable("tree capacity invariant"))?;
        }
        self.tree = tree;
        for nf in nfs {
            self.nullifiers.insert_checked(nf, Some(budget))?;
        }
        self.effects.insert_checked(effect, Some(budget))?;
        for entry in entries {
            self.recovery.push(Arc::new(entry))?;
        }
        self.accepted_outputs.push(Arc::new(linkage))?;
        self.pool = next_pool;
        self.burned = next_burned;
        Ok(EffectOutcome::Accepted)
    }

    fn append_position(&mut self, v: &VerifiedVertex) -> Result<()> {
        let candidate = v.candidate();
        let h = &candidate.header;
        let i = (self.executed.len() as u64)
            .checked_add(1)
            .ok_or(Error::Invalid("eligible cursor overflow"))?;
        if self.executed.len() >= 4096 {
            return Err(Error::Paused("eligible reference horizon"));
        }
        self.j = fold_j(&self.domain, self.j, i, candidate.id);
        self.executed.push(VertexId::from_bytes(candidate.id))?;
        let mut row = [0; 56];
        row[..8].copy_from_slice(&(i - 1).to_le_bytes());
        row[8..40].copy_from_slice(&candidate.id);
        row[40..48].copy_from_slice(&h.timestamp.to_le_bytes());
        row[48..56].copy_from_slice(&h.work.to_le_bytes());
        self.tail.push_back(row);
        if self.tail.len() > 43 {
            self.tail.pop_front();
        }
        let mut kr = Vec::with_capacity(176);
        kr.extend_from_slice(&i.to_le_bytes());
        kr.extend_from_slice(&candidate.id);
        kr.extend_from_slice(&h.source_index.to_le_bytes());
        for x in [
            &h.source_checkpoint,
            &h.source_j,
            &h.seed,
            &randomx_v2_work_key_id(v.facts().key_material),
        ] {
            kr.extend_from_slice(x);
        }
        debug_assert_eq!(kr.len(), 176);
        self.kc = domain_hash(
            "SilkNode-F01-key-carry-step",
            &[&self.domain, &self.kc, &kr],
        );
        let mut r = [0; 112];
        r[..8].copy_from_slice(&i.to_le_bytes());
        r[8..40].copy_from_slice(&candidate.id);
        r[40..72].copy_from_slice(&h.owner);
        r[72..104].copy_from_slice(&h.reward_nonce);
        r[104..].copy_from_slice(&PUBLIC_CREDIT_V1.to_le_bytes());
        self.rewards.push(r)?;
        self.issued = u128::from(i) * u128::from(PUBLIC_CREDIT_V1);
        Ok(())
    }

    fn daa_carry(&self) -> Digest {
        let mut b = Vec::with_capacity(124 + 56 * self.tail.len());
        b.extend_from_slice(b"SNDCF001\x01\0\0\0");
        b.extend_from_slice(&self.domain);
        b.extend_from_slice(&self.parameters);
        b.extend_from_slice(&(self.executed.len() as u64).to_le_bytes());
        b.extend_from_slice(&self.j);
        b.push(self.tail.len() as u8);
        b.extend_from_slice(&[0; 7]);
        for row in &self.tail {
            b.extend_from_slice(row);
        }
        domain_hash("SilkNode-F01-DAA-carry", &[&b])
    }

    fn hash_state(&self) -> Digest {
        self.hash_state_checked(None)
            .expect("unbudgeted state hashing")
    }
    fn hash_state_checked(&self, budget: Option<&crate::budget::JobBudget>) -> Result<Digest> {
        let check = || budget.map_or(Ok(()), crate::budget::JobBudget::check);
        check()?;
        let nf = hash_visit_checked(
            "SilkNode-F0-NF",
            &self.domain,
            self.nullifiers.len(),
            budget,
            |visit| self.nullifiers.visit_encoded(budget, visit),
        )?;
        check()?;
        let ef = hash_visit_checked(
            "SilkNode-F0-EF",
            &self.domain,
            self.effects.len(),
            budget,
            |visit| self.effects.visit_encoded(budget, visit),
        )?;
        check()?;
        let rh = hash_visit_checked(
            "SilkNode-F0-recovery-history",
            &self.domain,
            self.recovery.len(),
            budget,
            |visit| self.recovery.visit_encoded(budget, visit),
        )?;
        check()?;
        let pr = hash_visit_checked(
            "SilkNode-F0-public-rewards",
            &self.domain,
            self.rewards.len(),
            budget,
            |visit| self.rewards.visit_encoded(budget, visit),
        )?;
        check()?;
        Ok(domain_hash(
            "SilkNode-F0-state",
            &[
                &self.domain,
                &self.root(),
                &self.leaves().to_le_bytes(),
                &nf,
                &ef,
                &self.pool.to_le_bytes(),
                &self.burned.to_le_bytes(),
                &rh,
                &pr,
                &self.issued.to_le_bytes(),
            ],
        ))
    }

    fn check_invariants(&self) -> Result<()> {
        self.check_invariants_checked(None)
    }
    fn check_invariants_checked(&self, budget: Option<&crate::budget::JobBudget>) -> Result<()> {
        self.economic_counts()
            .validate_counts(&self.domain, self.initial_pool)
            .map_err(|_| Error::Unavailable("complete economic ledger invariants"))?;
        let mut prefix = self.executed.prefix_comparison();
        let mut position = 0;
        self.rewards.visit_encoded(budget, &mut |bytes| {
            let row: &[u8; 112] = bytes
                .try_into()
                .map_err(|_| Error::Unavailable("reward history item"))?;
            let vertex = VertexId::from_bytes(row[8..40].try_into().expect("fixed reward row"));
            crate::economics::validate_reward(position, &vertex, row)
                .map_err(|_| Error::Unavailable("complete economic ledger invariants"))?;
            prefix.advance(&vertex, budget)?;
            position += 1;
            Ok(())
        })?;
        if position != self.executed.len() || prefix.finish(budget)? != position {
            return Err(Error::Unavailable("complete economic ledger invariants"));
        }
        let mut last_position: Option<u64> = None;
        self.accepted_outputs.visit_encoded(budget, &mut |row| {
            last_position = Some(crate::wire::u64le(row, 32)?);
            Ok(())
        })?;
        if self.nullifiers.len() != self.effects.len() * 2
            || self.accepted_outputs.len() != self.effects.len()
            || last_position.is_some_and(|position| position.checked_add(2) != Some(self.leaves()))
            || self.leaves() != self.initial_leaves + 2 * self.burned
            || self.tree.size() as u64 != self.leaves()
        {
            return Err(Error::Unavailable("complete state invariants"));
        }
        budget.map_or(Ok(()), crate::budget::JobBudget::check)?;
        Ok(())
    }

    // Conservative cache charge counts shared ciphertexts afresh, so sharing can
    // only reduce actual use; includes collection node/allocator slack.
    pub(crate) const fn cache_charge(&self) -> usize {
        8192 + self.recovery.len() * 1024
            + self.recovery.cache_charge()
            + self.nullifiers.len() * 128
            + self.effects.len() * 128
            + self.accepted_outputs.len() * 192
            + self.accepted_outputs.cache_charge()
            + self.rewards.cache_charge()
            + self.executed.cache_charge()
            + self.cuts.len() * 256
    }

    /// Local-only materialized state manifest. Sets/history are the immutable
    /// genesis plus linked reversible deltas; their exact hashes are in the
    /// checkpoint state digest. Reopen recomputes and byte-compares this manifest.
    pub(crate) fn manifest(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"SNF04ST1");
        b.extend_from_slice(&(self.checkpoint.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.checkpoint);
        for v in [
            self.initial_leaves,
            self.initial_pool,
            self.leaves(),
            self.pool,
            self.burned,
            self.nullifiers.len() as u64,
            self.effects.len() as u64,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for h in [
            &self.domain,
            &self.parameters,
            &self.state_digest,
            &self.checkpoint_id,
            &self.prefix,
            &self.j,
            &self.dc,
            &self.kc,
        ] {
            b.extend_from_slice(h);
        }
        b.extend_from_slice(&self.issued.to_le_bytes());
        let frontier = self.tree.to_frontier();
        if let Some(f) = frontier.value() {
            b.push(1);
            b.extend_from_slice(&u64::from(f.position()).to_le_bytes());
            b.extend_from_slice(&f.leaf().to_bytes());
            b.push(f.ommers().len() as u8);
            for n in f.ommers() {
                b.extend_from_slice(&n.to_bytes());
            }
        } else {
            b.push(0);
        }
        b.push(self.tail.len() as u8);
        for row in &self.tail {
            b.extend_from_slice(row);
        }
        b.extend_from_slice(&(self.cuts.len() as u64).to_le_bytes());
        for c in &self.cuts {
            b.extend_from_slice(&c.index.to_le_bytes());
            for h in [&c.prefix, &c.root, &c.id] {
                b.extend_from_slice(h);
            }
            b.extend_from_slice(&c.leaves.to_le_bytes());
        }
        b
    }

    #[cfg(test)]
    pub(crate) fn delta(
        &self,
        prior: &Self,
        outcomes: &[EffectOutcome],
        rollback: bool,
    ) -> Result<Vec<u8>> {
        self.delta_checked(prior, outcomes, rollback, None)
    }
    pub(crate) fn delta_checked(
        &self,
        prior: &Self,
        outcomes: &[EffectOutcome],
        rollback: bool,
        budget: Option<&crate::budget::JobBudget>,
    ) -> Result<Vec<u8>> {
        let check = || budget.map_or(Ok(()), crate::budget::JobBudget::check);
        check()?;
        let mut b = Vec::new();
        b.extend_from_slice(b"SNF04DL1");
        b.push(u8::from(rollback));
        b.extend_from_slice(&[0; 7]);
        b.extend_from_slice(&prior.checkpoint_id);
        b.extend_from_slice(&self.checkpoint_id);
        b.extend_from_slice(&(outcomes.len() as u32).to_le_bytes());
        for o in outcomes {
            b.push(match o {
                EffectOutcome::Accepted => 0,
                EffectOutcome::IneligibleCut => 1,
                EffectOutcome::Duplicate => 2,
                EffectOutcome::Conflict => 3,
                EffectOutcome::Bounds => 4,
            });
        }
        if rollback {
            // Both complete state manifests and the immutable head lineage name
            // every reversed delta. No set union or partial balance restoration.
            for state in [prior, self] {
                let m = state.manifest();
                b.extend_from_slice(&(m.len() as u32).to_le_bytes());
                b.extend_from_slice(&m);
            }
        } else {
            if prior.executed.len().checked_add(8) != Some(self.executed.len()) {
                return Err(Error::Unavailable("delta prefix"));
            }
            let mut prefix = prior.executed.prefix_comparison();
            self.executed.visit_encoded(budget, &mut |row| {
                let id = VertexId::from_bytes(
                    row.try_into()
                        .map_err(|_| Error::Unavailable("delta executed width"))?,
                );
                prefix.advance(&id, budget)
            })?;
            if prefix.finish(budget)? != prior.executed.len() {
                return Err(Error::Unavailable("delta prefix"));
            }
            for set in [&self.nullifiers, &self.effects]
                .into_iter()
                .zip([&prior.nullifiers, &prior.effects])
            {
                let count_at = b.len();
                b.extend_from_slice(&0_u32.to_le_bytes());
                let mut count = 0_u32;
                set.0.difference_visit(set.1, budget, &mut |x| {
                    count = count
                        .checked_add(1)
                        .ok_or(Error::Unavailable("delta set count"))?;
                    b.extend_from_slice(x);
                    Ok(())
                })?;
                b[count_at..count_at + 4].copy_from_slice(&count.to_le_bytes());
            }
            let added_len = self
                .recovery
                .len()
                .checked_sub(prior.recovery.len())
                .ok_or(Error::Unavailable("delta recovery prefix"))?;
            let added_count =
                u32::try_from(added_len).map_err(|_| Error::Unavailable("delta recovery count"))?;
            b.extend_from_slice(&added_count.to_le_bytes());
            let mut position = 0;
            self.recovery.visit_encoded(budget, &mut |row| {
                if position >= prior.recovery.len() {
                    b.extend_from_slice(row);
                }
                position += 1;
                Ok(())
            })?;
            if prior.rewards.len() > self.rewards.len() {
                return Err(Error::Unavailable("delta reward prefix"));
            }
            let mut position = 0;
            self.rewards.visit_encoded(budget, &mut |row| {
                if position >= prior.rewards.len() {
                    b.extend_from_slice(row);
                }
                position += 1;
                Ok(())
            })?;
        }
        check()?;
        Ok(b)
    }

    pub(crate) fn materialize_ledger(
        &self,
        budget: Option<&crate::budget::JobBudget>,
    ) -> Result<Self> {
        let mut state = self.clone();
        state.recovery = self.recovery.materialize(budget)?;
        state.nullifiers = self.nullifiers.materialize(budget)?;
        state.effects = self.effects.materialize(budget)?;
        state.accepted_outputs = self.accepted_outputs.materialize(budget)?;
        state.rewards = self.rewards.materialize(budget)?;
        state.executed = self.executed.materialize(budget)?;
        Ok(state)
    }
    /// Private metadata clone only; append payloads and edited leaves are local
    /// staging, not a validity receipt. Completed transitions qualify all rows.
    fn prepare_ledger_mutation(&self, budget: &crate::budget::JobBudget) -> Result<Self> {
        budget.check()?;
        Ok(self.clone())
    }
    pub(crate) fn qualify_ledger_checked(&self, budget: &crate::budget::JobBudget) -> Result<()> {
        if self.hash_state_checked(Some(budget))? != self.state_digest {
            return Err(Error::Unavailable("retained state digest mismatch"));
        }
        self.check_invariants_checked(Some(budget))?;
        budget.check()
    }
    pub(crate) fn retain_ledger(
        &self,
        store: &mut crate::store::Store,
        budget: &crate::budget::JobBudget,
    ) -> Result<Self> {
        let mut state = self.clone();
        state.recovery = self.recovery.retain(store, self.domain, budget)?;
        state.nullifiers = self
            .nullifiers
            .retain(store, self.domain, *b"SNF04NP1", budget)?;
        state.effects = self
            .effects
            .retain(store, self.domain, *b"SNF04EP1", budget)?;
        state.accepted_outputs = self.accepted_outputs.retain(store, self.domain, budget)?;
        state.rewards = self.rewards.retain(store, self.domain, budget)?;
        state.executed = self.executed.retain(store, self.domain, budget)?;
        Ok(state)
    }
    #[cfg(test)]
    pub(crate) fn retained_set_pages(&self) -> [Vec<Digest>; 2] {
        [self.nullifiers.retained_ids(), self.effects.retained_ids()]
    }
    #[cfg(test)]
    pub(crate) fn retained_history_pages(&self) -> [Vec<Digest>; 3] {
        [
            self.accepted_outputs.retained_ids(),
            self.rewards.retained_ids(),
            self.executed.retained_ids(),
        ]
    }
    #[cfg(test)]
    pub(crate) fn retained_recovery_pages(&self) -> Vec<Digest> {
        self.recovery.retained_ids()
    }
    #[cfg(test)]
    pub(crate) fn staged_payload_counts(&self) -> [usize; 6] {
        [
            self.nullifiers.staged_keys(),
            self.effects.staged_keys(),
            self.recovery.staged_rows(),
            self.accepted_outputs.staged_rows(),
            self.rewards.staged_rows(),
            self.executed.staged_rows(),
        ]
    }
    #[cfg(test)]
    pub(crate) fn retained_payload_layout(&self) -> [bool; 6] {
        [
            self.nullifiers.has_retained_prefix(),
            self.effects.has_retained_prefix(),
            self.recovery.has_retained_prefix(),
            self.accepted_outputs.has_retained_prefix(),
            self.rewards.has_retained_prefix(),
            self.executed.has_retained_prefix(),
        ]
    }
    /// Canonical next-checkpoint maturity (not finality).
    #[must_use]
    pub fn eligible_cut(&self) -> &Cut {
        &self.cuts[eligible_cut_index(self.checkpoint_index + 1) as usize]
    }
    /// Complete canonical cut catalog, including immature cuts.
    #[must_use]
    pub fn cuts(&self) -> &[Cut] {
        &self.cuts
    }
    /// Public state digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.state_digest
    }
    /// Current complete checkpoint-prefix Q, not eligible-position J or cut Q.
    #[must_use]
    pub const fn prefix_commitment(&self) -> Digest {
        self.prefix
    }
    /// Complete current checkpoint bytes (136 at genesis, then 484).
    #[must_use]
    pub fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint
    }
    /// Exact current checkpoint ID.
    #[must_use]
    pub const fn checkpoint_id(&self) -> Digest {
        self.checkpoint_id
    }
    /// Number of completed checkpoints.
    #[must_use]
    pub const fn checkpoint_index(&self) -> u64 {
        self.checkpoint_index
    }
    /// F0 eligible-prefix fold J.
    #[must_use]
    pub const fn eligible_commitment(&self) -> Digest {
        self.j
    }
    /// Completed eligible IDs only; an incomplete interval is graph evidence.
    /// Materializes a complete compatibility view on demand, not for core replay.
    #[must_use]
    pub fn executed(&self) -> &[VertexId] {
        self.executed.as_slice()
    }
    pub(crate) const fn executed_len(&self) -> usize {
        self.executed.len()
    }
    #[cfg(test)]
    pub(crate) fn common_executed_prefix(&self, ids: &[VertexId]) -> usize {
        self.common_executed_prefix_checked(ids, None).unwrap()
    }
    pub(crate) fn common_executed_prefix_checked(
        &self,
        ids: &[VertexId],
        budget: Option<&crate::budget::JobBudget>,
    ) -> Result<usize> {
        let mut comparison = self.executed.prefix_comparison();
        for id in ids {
            comparison.advance(id, budget)?;
        }
        comparison.finish(budget)
    }
    pub(crate) const fn execution_comparison(&self) -> ExecutionComparison<'_> {
        ExecutionComparison(self.executed.prefix_comparison())
    }
    #[cfg(test)]
    pub(crate) fn executed_prefix_matches(&self, ids: &[VertexId]) -> bool {
        self.executed.len() <= ids.len() && self.common_executed_prefix(ids) == self.executed.len()
    }
    pub(crate) fn executed_prefix_matches_checked(
        &self,
        ids: &[VertexId],
        budget: Option<&crate::budget::JobBudget>,
    ) -> Result<bool> {
        Ok(self.executed.len() <= ids.len()
            && self.common_executed_prefix_checked(ids, budget)? == self.executed.len())
    }
    /// Public pool and cumulative private burn counters.
    #[must_use]
    pub const fn private_counters(&self) -> (u64, u64) {
        (self.pool, self.burned)
    }
    /// Position-bound ordered recovery history, including genesis.
    /// Materializes a compatibility view on demand; scanners use ordered reads.
    #[must_use]
    pub fn recovery(&self) -> &[Arc<[u8; RECOVERY_BYTES]>] {
        self.recovery.as_slice()
    }
    pub(crate) const fn recovery_len(&self) -> usize {
        self.recovery.len()
    }
    pub(crate) fn recovery_iter(&self) -> impl Iterator<Item = &Arc<[u8; RECOVERY_BYTES]>> {
        self.recovery.iter()
    }
    pub(crate) fn recovery_entry(&self, position: usize) -> Option<&Arc<[u8; RECOVERY_BYTES]>> {
        self.recovery.get(position)
    }
    /// Derived accepted-order output linkage. Restored by whole-state rollback and
    /// rebuilt through the reducer on replay, never adopted from received metadata.
    #[must_use]
    pub fn accepted_outputs(&self) -> &[Arc<AcceptedOutputs>] {
        self.accepted_outputs.as_slice()
    }
    pub(crate) fn accepted_outputs_iter(&self) -> impl Iterator<Item = &Arc<AcceptedOutputs>> {
        self.accepted_outputs.iter()
    }
    /// Genesis outputs have no retained value commitment for ordinary OVK recovery.
    #[must_use]
    pub const fn genesis_leaves(&self) -> u64 {
        self.initial_leaves
    }
    /// Spentness at this complete canonical state.
    #[must_use]
    pub fn contains_nullifier(&self, nf: &Digest) -> bool {
        self.nullifiers.contains(nf)
    }
    /// Exact economic-effect acceptance at this reversible canonical snapshot.
    /// This does not establish delivery of a particular authorization encoding.
    #[must_use]
    pub fn contains_effect(&self, effect: &Digest) -> bool {
        self.effects.contains(effect)
    }
    /// Current leaf count.
    #[must_use]
    pub fn leaves(&self) -> u64 {
        self.recovery.len() as u64
    }
    /// Standard Sapling note root.
    #[must_use]
    pub fn root(&self) -> Digest {
        self.tree.root().to_bytes()
    }
    /// Borrow complete receiver-derived accounting through compatibility slices.
    /// Complete slice views are materialized once on demand for compatibility.
    /// This is not a consensus proof or a transferable credit balance.
    #[must_use]
    pub fn economic_ledger(&self) -> EconomicLedgerV1<'_> {
        EconomicLedgerV1 {
            domain: self.domain,
            private_pool: self.pool,
            private_burned: self.burned,
            accepted_effects: self.effects.len() as u64,
            public_issued: self.issued,
            executed: self.executed.as_slice(),
            reward_records: self.rewards.as_slice(),
        }
    }
    const fn economic_counts(&self) -> EconomicCountsV1 {
        EconomicCountsV1 {
            domain: self.domain,
            private_pool: self.pool,
            private_burned: self.burned,
            accepted_effects: self.effects.len() as u64,
            public_issued: self.issued,
            executed: self.executed.len(),
            rewards: self.rewards.len(),
        }
    }
    /// Issued/mature public nontransferable attribution credits.
    #[must_use]
    pub fn public_balance(&self, owner: &Digest) -> (u128, u128) {
        let mut issued = 0;
        let mut mature = 0;
        for r in self.rewards.iter() {
            if r[40..72] == *owner {
                issued += u128::from(PUBLIC_CREDIT_V1);
                let i = u64::from_le_bytes(r[..8].try_into().expect("fixed reward"));
                if u128::from(i) + u128::from(CREDIT_MATURITY_V1) <= self.executed.len() as u128 {
                    mature += u128::from(PUBLIC_CREDIT_V1);
                }
            }
        }
        (issued, mature)
    }
}

/// Largest eligible cut at execution checkpoint j. Genesis cut is the explicit exception.
#[must_use]
pub const fn eligible_cut_index(j: u64) -> u64 {
    j.saturating_sub(1).saturating_div(128).saturating_sub(2)
}

pub(crate) fn fold_j(n: &Digest, prior: Digest, position: u64, id: Digest) -> Digest {
    domain_hash(
        "SilkNode-F0-eligible",
        &[n, &prior, &position.to_le_bytes(), &id],
    )
}
#[cfg(test)]
fn hash_stream<'a>(
    label: &'static str,
    n: &Digest,
    count: usize,
    entries: impl Iterator<Item = &'a [u8]>,
) -> Digest {
    hash_stream_checked(label, n, count, entries, None).unwrap()
}
#[cfg(test)]
fn hash_stream_checked<'a>(
    label: &'static str,
    n: &Digest,
    count: usize,
    entries: impl Iterator<Item = &'a [u8]>,
    budget: Option<&crate::budget::JobBudget>,
) -> Result<Digest> {
    let mut h = Sha256::new();
    h.update([label.len() as u8]);
    h.update(label.as_bytes());
    h.update(n);
    h.update((count as u64).to_le_bytes());
    for (i, entry) in entries.enumerate() {
        if i % 64 == 0 {
            if let Some(budget) = budget {
                budget.check()?;
            }
        }
        h.update(entry);
    }
    Ok(h.finalize().into())
}

fn hash_visit_checked(
    label: &'static str,
    n: &Digest,
    count: usize,
    budget: Option<&crate::budget::JobBudget>,
    source: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>,
) -> Result<Digest> {
    let check = || budget.map_or(Ok(()), crate::budget::JobBudget::check);
    check()?;
    let mut h = Sha256::new();
    h.update([label.len() as u8]);
    h.update(label.as_bytes());
    h.update(n);
    h.update((count as u64).to_le_bytes());
    let mut seen = 0_usize;
    source(&mut |row| {
        if seen % 64 == 0 {
            check()?;
        }
        if seen >= count {
            return Err(Error::Unavailable("streamed ledger hash count"));
        }
        h.update(row);
        seen += 1;
        Ok(())
    })?;
    if seen != count {
        return Err(Error::Unavailable("streamed ledger hash count"));
    }
    check()?;
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn set_key(position: u16) -> Digest {
        let mut key = [0; 32];
        key[30..].copy_from_slice(&position.to_be_bytes());
        key
    }

    // Synthetic ordered accounting rows, not mined or cryptographically admitted
    // checkpoints. These exercise representation and private core read adapters.
    // The recovery fixtures below likewise construct private synthetic rows and
    // accounting only. They are NOT accepted payments, encrypted recovery or a
    // network/reorganization acceptance experiment.
    fn append_recovery_rows(state: &mut BranchState, labels: std::ops::RangeInclusive<u16>) {
        for label in labels {
            let first_position = state.leaves();
            for slot in 0..2_u16 {
                let mut row = [0; RECOVERY_BYTES];
                row[32..34].copy_from_slice(&label.to_le_bytes());
                row[34..36].copy_from_slice(&slot.to_le_bytes());
                let node = Option::<Node>::from(Node::from_bytes([0; 32])).unwrap();
                state.tree.append(node).unwrap();
                state.recovery.push(Arc::new(row)).unwrap();
                state
                    .nullifiers
                    .insert(set_key(1000 + label * 2 + slot))
                    .unwrap();
            }
            let effect = set_key(label);
            state.effects.insert(effect).unwrap();
            state
                .accepted_outputs
                .push(Arc::new(AcceptedOutputs {
                    effect,
                    first_position,
                    commitments: [set_key(label), set_key(label + 100)],
                }))
                .unwrap();
            state.pool -= PRIVATE_BURN_V1;
            state.burned += PRIVATE_BURN_V1;
        }
    }
    fn recovery_fixture(count: u16) -> BranchState {
        let (mut state, _, _) = ordered_fixture(64);
        state.initial_pool = 100;
        state.pool = 100;
        append_recovery_rows(&mut state, 1..=count);
        state.state_digest = state.hash_state();
        state.check_invariants().unwrap();
        state
    }

    #[test]
    fn streaming_state_hash_matches_literal_collections_and_refuses_every_late_page() {
        // Synthetic economic/storage model only, not admitted payments, work,
        // encrypted recovery, competing peers or a native checkpoint journey.
        let (mut state, _, _) = ordered_fixture(136);
        state.initial_pool = 100;
        state.pool = 100;
        append_recovery_rows(&mut state, 1..=70);
        state.check_invariants().unwrap();
        let nf = hash_stream(
            "SilkNode-F0-NF",
            &state.domain,
            state.nullifiers.len(),
            state.nullifiers.iter().map(Digest::as_slice),
        );
        let ef = hash_stream(
            "SilkNode-F0-EF",
            &state.domain,
            state.effects.len(),
            state.effects.iter().map(Digest::as_slice),
        );
        let rh = hash_stream(
            "SilkNode-F0-recovery-history",
            &state.domain,
            state.recovery.len(),
            state.recovery.iter().map(|row| row.as_slice()),
        );
        let pr = hash_stream(
            "SilkNode-F0-public-rewards",
            &state.domain,
            state.rewards.len(),
            state.rewards.iter().map(<[u8; 112]>::as_slice),
        );
        let expected = domain_hash(
            "SilkNode-F0-state",
            &[
                &state.domain,
                &state.root(),
                &state.leaves().to_le_bytes(),
                &nf,
                &ef,
                &state.pool.to_le_bytes(),
                &state.burned.to_le_bytes(),
                &rh,
                &pr,
                &state.issued.to_le_bytes(),
            ],
        );
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic streamed complete ledger hashes")
            .unwrap();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        assert_eq!(state.hash_state_checked(Some(&budget)).unwrap(), expected);
        let stored = state.retain_ledger(&mut store, &budget).unwrap();
        let before = stored.manifest();
        assert_eq!(stored.hash_state_checked(Some(&budget)).unwrap(), expected);
        let pages = [
            stored.retained_set_pages()[0].clone(),
            stored.retained_set_pages()[1].clone(),
            stored.retained_recovery_pages(),
            stored.retained_history_pages()[1].clone(),
        ];
        assert!(pages.iter().all(|pages| pages.len() >= 2));
        for pages in pages {
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(pages.last().unwrap())));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(stored.hash_state_checked(Some(&budget)).is_err());
            std::fs::rename(&held, &path).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut changed = bytes.clone();
            *changed.last_mut().unwrap() ^= 1;
            std::fs::write(&path, changed).unwrap();
            assert!(stored.hash_state_checked(Some(&budget)).is_err());
            std::fs::write(&path, bytes).unwrap();
            std::fs::hard_link(&path, &held).unwrap();
            assert!(stored.hash_state_checked(Some(&budget)).is_err());
            std::fs::remove_file(&held).unwrap();
            assert_eq!(stored.hash_state_checked(Some(&budget)).unwrap(), expected);
            assert_eq!(stored.manifest(), before);
        }
        let expired = crate::budget::JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(stored.hash_state_checked(Some(&expired)).is_err());
        assert!(
            hash_visit_checked("fixture", &state.domain, 1, Some(&budget), |_| Ok(())).is_err()
        );
        assert!(
            hash_visit_checked("fixture", &state.domain, 0, Some(&budget), |visit| visit(
                b"extra"
            ))
            .is_err()
        );
        assert_eq!(store.head(), None);
        assert_eq!(stored.manifest(), before);
    }

    #[test]
    fn paged_recovery_history_views_preserve_positions_and_share_ciphertexts() {
        let state = recovery_fixture(70);
        let expected = state.recovery_iter().cloned().collect::<Vec<_>>();
        let links = state.accepted_outputs_iter().cloned().collect::<Vec<_>>();
        assert_eq!(expected.len(), 140);
        assert_eq!(links.len(), 70);
        for position in [0, 63, 64, 127, 128, 139] {
            assert!(Arc::ptr_eq(
                state.recovery_entry(position).unwrap(),
                &expected[position]
            ));
        }
        assert!(state.recovery_entry(140).is_none());
        assert!(state.recovery_entry(usize::MAX).is_none());
        assert!(!state.recovery.is_materialized());
        assert!(!state.accepted_outputs.is_materialized());
        let charge = state.cache_charge();
        assert_eq!(state.recovery(), expected);
        assert_eq!(state.accepted_outputs(), links);
        assert_eq!(state.cache_charge(), charge);
        let cloned = state.clone();
        cloned.check_invariants().unwrap();
        assert!(!cloned.recovery.is_materialized());
        assert!(!cloned.accepted_outputs.is_materialized());
        assert!(Arc::ptr_eq(
            cloned.recovery_entry(64).unwrap(),
            &expected[64]
        ));
        assert_eq!(cloned.manifest(), state.manifest());
    }

    #[test]
    fn paged_recovery_history_state_hash_and_both_deltas_match_flat_bytes() {
        let prior = recovery_fixture(64);
        let original = prior.manifest();
        let mut next = prior.clone();
        append_recovery_rows(&mut next, 65..=70);
        let (_, ids, rewards) = ordered_fixture(72);
        for (id, reward) in ids[64..].iter().zip(&rewards[64..]) {
            next.executed.push(*id).unwrap();
            next.rewards.push(*reward).unwrap();
        }
        next.issued = 720;
        next.checkpoint_index = 9;
        next.checkpoint_id = [9; 32];
        next.state_digest = next.hash_state();
        next.check_invariants().unwrap();
        let flat = next.recovery_iter().cloned().collect::<Vec<_>>();
        let nf = hash_stream(
            "SilkNode-F0-NF",
            &next.domain,
            next.nullifiers.len(),
            next.nullifiers.iter().map(|x| x.as_slice()),
        );
        let ef = hash_stream(
            "SilkNode-F0-EF",
            &next.domain,
            next.effects.len(),
            next.effects.iter().map(|x| x.as_slice()),
        );
        let rh = hash_stream(
            "SilkNode-F0-recovery-history",
            &next.domain,
            flat.len(),
            flat.iter().map(|row| row.as_slice()),
        );
        let pr = hash_stream(
            "SilkNode-F0-public-rewards",
            &next.domain,
            rewards.len(),
            rewards.iter().map(|row| row.as_slice()),
        );
        let expected = domain_hash(
            "SilkNode-F0-state",
            &[
                &next.domain,
                &next.root(),
                &140_u64.to_le_bytes(),
                &nf,
                &ef,
                &30_u64.to_le_bytes(),
                &70_u64.to_le_bytes(),
                &rh,
                &pr,
                &720_u128.to_le_bytes(),
            ],
        );
        assert_eq!(next.hash_state(), expected);
        let mut delta = Vec::from(b"SNF04DL1\0\0\0\0\0\0\0\0".as_slice());
        delta.extend_from_slice(&prior.checkpoint_id);
        delta.extend_from_slice(&next.checkpoint_id);
        delta.extend_from_slice(&0_u32.to_le_bytes());
        for (new, old) in [
            (&next.nullifiers, &prior.nullifiers),
            (&next.effects, &prior.effects),
        ] {
            let added = new.difference(old).collect::<Vec<_>>();
            delta.extend_from_slice(&u32::try_from(added.len()).unwrap().to_le_bytes());
            for row in added {
                delta.extend_from_slice(row);
            }
        }
        delta.extend_from_slice(&12_u32.to_le_bytes());
        for row in &flat[128..] {
            delta.extend_from_slice(row.as_slice());
        }
        for row in &rewards[64..] {
            delta.extend_from_slice(row);
        }
        assert_eq!(next.delta(&prior, &[], false).unwrap(), delta);
        let mut rollback = Vec::from(b"SNF04DL1\x01\0\0\0\0\0\0\0".as_slice());
        rollback.extend_from_slice(&next.checkpoint_id);
        rollback.extend_from_slice(&prior.checkpoint_id);
        rollback.extend_from_slice(&0_u32.to_le_bytes());
        for state in [&next, &prior] {
            let manifest = state.manifest();
            rollback.extend_from_slice(&u32::try_from(manifest.len()).unwrap().to_le_bytes());
            rollback.extend_from_slice(&manifest);
        }
        assert_eq!(prior.delta(&next, &[], true).unwrap(), rollback);
        assert!(!next.recovery.is_materialized());
        assert!(!next.accepted_outputs.is_materialized());
        assert_eq!(prior.manifest(), original);
        assert_eq!(prior.recovery_len(), 128);
        assert_eq!(prior.accepted_outputs_iter().count(), 64);
    }

    #[test]
    fn paged_recovery_history_witness_matches_flat_tree_without_materializing() {
        use sapling_crypto::IncrementalWitness;
        let mut state = recovery_fixture(70);
        state.cuts[0] = Cut::new(&state.domain, 0, state.prefix, state.root(), state.leaves());
        let cut = state.cuts[0].clone();
        let flat = state.recovery_iter().cloned().collect::<Vec<_>>();
        for position in [0, 63, 64, 127, 139] {
            let mut tree = CommitmentTree::empty();
            let mut witness = None;
            for (index, row) in flat.iter().enumerate() {
                let node =
                    Option::<Node>::from(Node::from_bytes(row[..32].try_into().unwrap())).unwrap();
                tree.append(node).unwrap();
                if let Some(w) = witness.as_mut() {
                    IncrementalWitness::append(w, node).unwrap();
                }
                if index == position {
                    witness = IncrementalWitness::from_tree(tree.clone());
                }
            }
            let actual = crate::scanner::witness_at_cut(&state, &cut, position as u64).unwrap();
            assert_eq!(actual, witness.unwrap().path().unwrap());
            assert_eq!(
                actual
                    .root(Option::<Node>::from(Node::from_bytes([0; 32])).unwrap())
                    .to_bytes(),
                cut.root
            );
        }
        assert!(crate::scanner::witness_at_cut(&state, &cut, 140).is_err());
        let mut changed = cut.clone();
        changed.root = [9; 32];
        assert!(crate::scanner::witness_at_cut(&state, &changed, 0).is_err());
        assert!(!state.recovery.is_materialized());
        assert!(!state.accepted_outputs.is_materialized());
    }

    fn ordered_fixture(count: u16) -> (BranchState, Vec<VertexId>, Vec<[u8; 112]>) {
        let genesis = crate::genesis::public_testnet_v1::genesis().unwrap();
        let mut state = BranchState::genesis(&genesis).unwrap();
        let mut ids = Vec::new();
        let mut rewards = Vec::new();
        for position in 1..=count {
            let id = VertexId::from_bytes(set_key(position));
            let mut row = [0; 112];
            row[..8].copy_from_slice(&u64::from(position).to_le_bytes());
            row[8..40].copy_from_slice(id.as_bytes());
            row[40..72].copy_from_slice(&[3; 32]);
            row[104..].copy_from_slice(&PUBLIC_CREDIT_V1.to_le_bytes());
            state.executed.push(id).unwrap();
            state.rewards.push(row).unwrap();
            state.j = fold_j(&state.domain, state.j, u64::from(position), id.into_bytes());
            ids.push(id);
            rewards.push(row);
        }
        state.issued = u128::from(count) * u128::from(PUBLIC_CREDIT_V1);
        state.checkpoint_index = u64::from(count) / 8;
        state.state_digest = state.hash_state();
        (state, ids, rewards)
    }

    #[test]
    fn streaming_order_ledger_inspection_matches_prefix_interval_and_refuses_late_damage() {
        // Synthetic private serializer rows, NOT work/crypto/checkpoint acceptance.
        let (state, ids, _) = ordered_fixture(136);
        let (prior, _, _) = ordered_fixture(128);
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic streaming comparison")
            .unwrap();
        let stored = state.retain_ledger(&mut store, &budget).unwrap();
        let prior = prior.retain_ledger(&mut store, &budget).unwrap();
        let mut bytes = Vec::from(b"SNF04OR1".as_slice());
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in &ids {
            bytes.extend_from_slice(id.as_bytes());
        }
        store
            .commit_ordered(&[], &bytes, b"synthetic inspection", &budget)
            .unwrap();
        let order = crate::core::order::CoreOrder::synthetic_retained(
            &bytes,
            store.object_reader().unwrap(),
        );
        let inspection = order
            .inspect(&[&stored, &prior], Some(128), &budget)
            .unwrap();
        assert_eq!(inspection.count, 136);
        assert_eq!(inspection.common, [136, 128]);
        assert_eq!(inspection.interval, ids[128..136]);
        assert_eq!(order.inspect(&[], None, &budget).unwrap().count, 136);
        assert!(order.inspect(&[&stored; 7], None, &budget).is_err());
        assert!(order.inspect(&[], Some(usize::MAX), &budget).is_err());
        let mut divergent = ids.clone();
        divergent[0] = VertexId::from_bytes([99; 32]);
        assert_eq!(
            stored
                .common_executed_prefix_checked(&divergent, Some(&budget))
                .unwrap(),
            0
        );
        assert_eq!(
            stored
                .common_executed_prefix_checked(&ids[..1], Some(&budget))
                .unwrap(),
            1
        );
        let executed_pages = stored.retained_history_pages()[2].clone();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(executed_pages[2])));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(order.inspect(&[&stored], Some(0), &budget).is_err());
        assert!(
            stored
                .common_executed_prefix_checked(&divergent, Some(&budget))
                .is_err()
        );
        assert!(
            stored
                .common_executed_prefix_checked(&[], Some(&budget))
                .is_err()
        );
        std::fs::rename(&held, &path).unwrap();
        let expired = crate::budget::JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(order.inspect(&[&stored], Some(0), &expired).is_err());
        assert_eq!(
            order
                .inspect(&[&stored], Some(128), &budget)
                .unwrap()
                .interval,
            ids[128..]
        );
    }

    #[test]
    fn retained_payment_model_and_rollback_qualification_match_literal_state_and_delta() {
        // Synthetic accepted-row model, NOT cryptographic/payment acceptance.
        let prior = recovery_fixture(70);
        let mut literal = prior.clone();
        let (ordered, _, _) = ordered_fixture(72);
        for row in ordered.executed.iter_from(64).unwrap() {
            literal.executed.push(*row).unwrap();
        }
        for row in ordered.rewards.iter_from(64).unwrap() {
            literal.rewards.push(*row).unwrap();
        }
        literal.issued = ordered.issued;
        literal.checkpoint_index = ordered.checkpoint_index;
        append_recovery_rows(&mut literal, 71..=74);
        literal.state_digest = literal.hash_state();
        literal.check_invariants().unwrap();
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic retained mutation and rollback")
            .unwrap();
        let base = prior.retain_ledger(&mut store, &budget).unwrap();
        base.qualify_ledger_checked(&budget).unwrap();
        let mut staged = base.prepare_ledger_mutation(&budget).unwrap();
        for row in ordered.executed.iter_from(64).unwrap() {
            staged.executed.push(*row).unwrap();
        }
        for row in ordered.rewards.iter_from(64).unwrap() {
            staged.rewards.push(*row).unwrap();
        }
        staged.issued = ordered.issued;
        staged.checkpoint_index = ordered.checkpoint_index;
        append_recovery_rows(&mut staged, 71..=74);
        staged.state_digest = staged.hash_state_checked(Some(&budget)).unwrap();
        staged.qualify_ledger_checked(&budget).unwrap();
        let counts = staged.staged_payload_counts();
        assert!(counts[0] <= 128 && counts[1] <= 128);
        assert_eq!(&counts[2..], &[8, 4, 8, 8]);
        assert_eq!(staged.manifest(), literal.manifest());
        assert_eq!(base.manifest(), prior.manifest());
        let outcomes = [EffectOutcome::Accepted; 4];
        assert_eq!(
            staged
                .delta_checked(&base, &outcomes, false, Some(&budget))
                .unwrap(),
            literal.delta(&prior, &outcomes, false).unwrap()
        );
        assert_eq!(
            base.delta_checked(&staged, &[], true, Some(&budget))
                .unwrap(),
            prior.delta(&literal, &[], true).unwrap()
        );
        let retained = staged.retain_ledger(&mut store, &budget).unwrap();
        let expected = literal.retain_ledger(&mut store, &budget).unwrap();
        assert_eq!(retained.retained_set_pages(), expected.retained_set_pages());
        assert_eq!(
            retained.retained_history_pages(),
            expected.retained_history_pages()
        );
        assert_eq!(
            retained.retained_recovery_pages(),
            expected.retained_recovery_pages()
        );
        assert_eq!(retained.staged_payload_counts(), [0; 6]);
        let mut pages = base.retained_set_pages().to_vec();
        pages.push(base.retained_recovery_pages());
        pages.extend(base.retained_history_pages());
        for ids in pages {
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(ids[0])));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(base.qualify_ledger_checked(&budget).is_err());
            assert!(staged.qualify_ledger_checked(&budget).is_err());
            std::fs::rename(&held, &path).unwrap();
        }
        assert_eq!(base.manifest(), prior.manifest());
        assert_eq!(staged.manifest(), literal.manifest());
        assert_eq!(store.head(), None);
    }

    #[test]
    fn mutation_preparation_retains_all_pages_and_checks_complete_invariants() {
        // Synthetic state only; selection from admitted bodies is covered by
        // native execution, not by this private preparation adapter fixture.
        let (mut state, _, _) = ordered_fixture(136);
        state.initial_pool = 100;
        state.pool = 100;
        append_recovery_rows(&mut state, 1..=70);
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic selective reducer preparation")
            .unwrap();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        let stored = state.retain_ledger(&mut store, &budget).unwrap();
        let before = stored.manifest();
        stored.check_invariants_checked(Some(&budget)).unwrap();
        let sparse = stored.prepare_ledger_mutation(&budget).unwrap();
        assert_eq!(sparse.retained_set_pages(), stored.retained_set_pages());
        assert_eq!(
            sparse.retained_recovery_pages(),
            stored.retained_recovery_pages()
        );
        assert_eq!(
            sparse.retained_history_pages()[0],
            stored.retained_history_pages()[0]
        );
        assert_eq!(
            sparse.retained_history_pages(),
            stored.retained_history_pages()
        );
        sparse.check_invariants_checked(Some(&budget)).unwrap();
        assert_eq!(
            sparse.hash_state_checked(Some(&budget)).unwrap(),
            state.hash_state()
        );
        let full = stored.materialize_ledger(Some(&budget)).unwrap();
        assert!(full.retained_set_pages().iter().all(Vec::is_empty));
        assert!(full.retained_recovery_pages().is_empty());
        assert!(full.retained_history_pages().iter().all(Vec::is_empty));
        assert_eq!(full.hash_state(), state.hash_state());
        let mut wrong = state.clone();
        wrong.executed = LedgerHistory::new(crate::sync::HISTORY_LIMIT_V1);
        for index in 0..136_u64 {
            wrong
                .executed
                .push(VertexId::from_bytes([index as u8; 32]))
                .unwrap();
        }
        assert!(wrong.check_invariants_checked(Some(&budget)).is_err());
        for pages in [
            stored.retained_history_pages()[0].clone(),
            stored.retained_history_pages()[1].clone(),
            stored.retained_history_pages()[2].clone(),
        ] {
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(pages.last().unwrap())));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(stored.check_invariants_checked(Some(&budget)).is_err());
            std::fs::rename(&held, &path).unwrap();
        }
        let expired = crate::budget::JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(stored.prepare_ledger_mutation(&expired).is_err());
        assert!(stored.check_invariants_checked(Some(&expired)).is_err());
        assert_eq!(stored.manifest(), before);
        assert_eq!(store.head(), None);
    }

    #[test]
    fn streaming_forward_delta_matches_literal_bytes_and_refuses_late_inputs() {
        // Synthetic serializer model only; no work/proof/payment acceptance.
        let (mut prior, _, _) = ordered_fixture(128);
        let (mut next, _, _) = ordered_fixture(136);
        for state in [&mut prior, &mut next] {
            state.initial_pool = 100;
            state.pool = 100;
        }
        append_recovery_rows(&mut prior, 1..=70);
        append_recovery_rows(&mut next, 1..=74);
        let outcomes = [EffectOutcome::Accepted, EffectOutcome::Duplicate];
        // Independent previous literal collection serializer.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"SNF04DL1");
        expected.extend_from_slice(&[0; 8]);
        expected.extend_from_slice(&prior.checkpoint_id);
        expected.extend_from_slice(&next.checkpoint_id);
        expected.extend_from_slice(&2_u32.to_le_bytes());
        expected.extend_from_slice(&[0, 2]);
        for (current, previous) in [
            (&next.nullifiers, &prior.nullifiers),
            (&next.effects, &prior.effects),
        ] {
            let added = current.difference(previous).collect::<Vec<_>>();
            expected.extend_from_slice(&(added.len() as u32).to_le_bytes());
            for key in added {
                expected.extend_from_slice(key);
            }
        }
        expected.extend_from_slice(
            &((next.recovery.len() - prior.recovery.len()) as u32).to_le_bytes(),
        );
        for row in next
            .recovery
            .resident()
            .iter_from(prior.recovery.len())
            .unwrap()
        {
            expected.extend_from_slice(row.as_slice());
        }
        for row in next.rewards.iter_from(prior.rewards.len()).unwrap() {
            expected.extend_from_slice(row);
        }
        assert_eq!(next.delta(&prior, &outcomes, false).unwrap(), expected);
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic streamed forward delta")
            .unwrap();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        let previous = prior.retain_ledger(&mut store, &budget).unwrap();
        let current = next.retain_ledger(&mut store, &budget).unwrap();
        let manifests = [previous.manifest(), current.manifest()];
        assert_eq!(
            current
                .delta_checked(&previous, &outcomes, false, Some(&budget))
                .unwrap(),
            expected
        );
        let mut pages = current.retained_set_pages().to_vec();
        pages.extend(previous.retained_set_pages());
        pages.push(current.retained_recovery_pages());
        pages.push(current.retained_history_pages()[1].clone());
        pages.push(current.retained_history_pages()[2].clone());
        pages.push(previous.retained_history_pages()[2].clone());
        for ids in pages {
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(ids.last().unwrap())));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(
                current
                    .delta_checked(&previous, &outcomes, false, Some(&budget))
                    .is_err()
            );
            std::fs::rename(&held, &path).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut changed = bytes.clone();
            *changed.last_mut().unwrap() ^= 1;
            std::fs::write(&path, changed).unwrap();
            assert!(
                current
                    .delta_checked(&previous, &outcomes, false, Some(&budget))
                    .is_err()
            );
            std::fs::write(&path, bytes).unwrap();
            std::fs::hard_link(&path, &held).unwrap();
            assert!(
                current
                    .delta_checked(&previous, &outcomes, false, Some(&budget))
                    .is_err()
            );
            std::fs::remove_file(&held).unwrap();
            assert_eq!(
                current
                    .delta_checked(&previous, &outcomes, false, Some(&budget))
                    .unwrap(),
                expected
            );
        }
        let expired = crate::budget::JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(
            current
                .delta_checked(&previous, &outcomes, false, Some(&expired))
                .is_err()
        );
        assert!(
            previous
                .delta_checked(&current, &outcomes, false, Some(&budget))
                .is_err()
        );
        assert_eq!([previous.manifest(), current.manifest()], manifests);
        assert_eq!(store.head(), None);
    }

    #[test]
    fn disk_history_state_prefix_hash_delta_and_public_accounting_match_resident_bytes() {
        // Private ordered-row serializer model, not native work or checkpoints.
        let (prior, ids, rewards) = ordered_fixture(64);
        let (next, _, _) = ordered_fixture(72);
        let expected_hash = prior.hash_state();
        let expected_delta = next.delta(&prior, &[], false).unwrap();
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic history state serializers")
            .unwrap();
        let stored_prior = prior.retain_ledger(&mut store, &budget).unwrap();
        let stored_next = next.retain_ledger(&mut store, &budget).unwrap();
        assert_eq!(
            stored_prior.hash_state_checked(Some(&budget)).unwrap(),
            expected_hash
        );
        assert_eq!(
            stored_next
                .delta_checked(&stored_prior, &[], false, Some(&budget))
                .unwrap(),
            expected_delta
        );
        assert_eq!(
            stored_prior
                .common_executed_prefix_checked(&ids, Some(&budget))
                .unwrap(),
            64
        );
        let mut fork = ids.clone();
        fork[61] = VertexId::from_bytes([99; 32]);
        assert_eq!(
            stored_prior
                .common_executed_prefix_checked(&fork, Some(&budget))
                .unwrap(),
            61
        );
        assert!(
            !stored_prior
                .executed_prefix_matches_checked(&fork, Some(&budget))
                .unwrap()
        );
        let restored = stored_prior.materialize_ledger(Some(&budget)).unwrap();
        restored.check_invariants().unwrap();
        assert_eq!(restored.executed(), ids);
        assert_eq!(restored.economic_ledger().reward_records, rewards);
        assert_eq!(
            restored.public_balance(&[3; 32]),
            prior.public_balance(&[3; 32])
        );
        for (kind, pages) in stored_prior
            .retained_history_pages()
            .into_iter()
            .enumerate()
        {
            if kind == 0 {
                continue;
            }
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(pages[0])));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(matches!(
                stored_prior.materialize_ledger(Some(&budget)),
                Err(Error::Io(_))
            ));
            if kind == 1 {
                assert!(matches!(
                    stored_prior.hash_state_checked(Some(&budget)),
                    Err(Error::Io(_))
                ));
            } else {
                assert!(matches!(
                    stored_prior.common_executed_prefix_checked(&ids, Some(&budget)),
                    Err(Error::Io(_))
                ));
                assert!(matches!(
                    stored_next.delta_checked(&stored_prior, &[], false, Some(&budget)),
                    Err(Error::Io(_))
                ));
            }
            std::fs::rename(&held, &path).unwrap();
        }
        assert_eq!(store.head(), None);
        assert_eq!(prior.hash_state(), expected_hash);
    }

    #[test]
    fn paged_ledger_sequence_accounting_prefix_and_balance_do_not_flatten() {
        let (state, ids, rewards) = ordered_fixture(64);
        state.check_invariants().unwrap();
        assert_eq!(state.common_executed_prefix(&ids), ids.len());
        assert!(state.executed_prefix_matches(&ids));
        assert!(!state.executed_prefix_matches(&ids[..63]));
        let mut fork = ids.clone();
        fork[61] = VertexId::from_bytes([99; 32]);
        assert_eq!(state.common_executed_prefix(&fork), 61);
        assert!(!state.executed_prefix_matches(&fork));
        assert_eq!(state.public_balance(&[3; 32]), (640, 480));
        assert!(!state.executed.is_materialized());
        assert!(!state.rewards.is_materialized());
        assert_eq!(state.executed(), ids);
        let view = state.economic_ledger();
        assert_eq!(view.reward_records, rewards);
        view.validate(&state.domain, 0).unwrap();
        assert!(state.executed.is_materialized());
        assert!(state.rewards.is_materialized());
        let cloned = state.clone();
        assert!(!cloned.executed.is_materialized());
        assert!(!cloned.rewards.is_materialized());
        cloned.check_invariants().unwrap();
        assert!(!cloned.executed.is_materialized());
        assert!(!cloned.rewards.is_materialized());
    }

    #[test]
    fn paged_ledger_sequence_reward_hash_and_reversible_delta_match_flat_rows() {
        let (prior, ids, rewards) = ordered_fixture(64);
        let before = prior.manifest();
        let mut next = prior.clone();
        let (_, next_ids, next_rewards) = ordered_fixture(72);
        for (id, row) in next_ids[64..].iter().zip(&next_rewards[64..]) {
            next.executed.push(*id).unwrap();
            next.rewards.push(*row).unwrap();
        }
        next.issued = 720;
        next.checkpoint_index = 9;
        next.checkpoint_id = [9; 32];
        next.state_digest = next.hash_state();
        next.check_invariants().unwrap();
        let nf = hash_stream("SilkNode-F0-NF", &next.domain, 0, std::iter::empty());
        let ef = hash_stream("SilkNode-F0-EF", &next.domain, 0, std::iter::empty());
        let rh = hash_stream(
            "SilkNode-F0-recovery-history",
            &next.domain,
            0,
            std::iter::empty(),
        );
        let pr = hash_stream(
            "SilkNode-F0-public-rewards",
            &next.domain,
            next_rewards.len(),
            next_rewards.iter().map(|row| row.as_slice()),
        );
        let expected = domain_hash(
            "SilkNode-F0-state",
            &[
                &next.domain,
                &next.root(),
                &0_u64.to_le_bytes(),
                &nf,
                &ef,
                &0_u64.to_le_bytes(),
                &0_u64.to_le_bytes(),
                &rh,
                &pr,
                &720_u128.to_le_bytes(),
            ],
        );
        assert_eq!(next.hash_state(), expected);
        let mut delta = Vec::from(b"SNF04DL1\0\0\0\0\0\0\0\0".as_slice());
        delta.extend_from_slice(&prior.checkpoint_id);
        delta.extend_from_slice(&next.checkpoint_id);
        for _ in 0..4 {
            delta.extend_from_slice(&0_u32.to_le_bytes());
        } // outcomes/NF/EF/recovery
        for row in &next_rewards[64..] {
            delta.extend_from_slice(row);
        }
        assert_eq!(next.delta(&prior, &[], false).unwrap(), delta);
        let mut rollback = Vec::from(b"SNF04DL1\x01\0\0\0\0\0\0\0".as_slice());
        rollback.extend_from_slice(&next.checkpoint_id);
        rollback.extend_from_slice(&prior.checkpoint_id);
        rollback.extend_from_slice(&0_u32.to_le_bytes());
        for state in [&next, &prior] {
            let manifest = state.manifest();
            rollback.extend_from_slice(&u32::try_from(manifest.len()).unwrap().to_le_bytes());
            rollback.extend_from_slice(&manifest);
        }
        assert_eq!(prior.delta(&next, &[], true).unwrap(), rollback);
        assert!(!next.executed.is_materialized());
        assert!(!next.rewards.is_materialized());
        assert_eq!(prior.manifest(), before);
        assert_eq!(prior.executed(), ids);
        assert_eq!(prior.economic_ledger().reward_records, rewards);
    }

    // Private serializer fixtures, NOT accepted effects/economic states. No
    // work, proof, payment or genuine checkpoint/reorganization is constructed.
    #[test]
    fn paged_ledger_set_state_hash_matches_literal_btree_streams() {
        let genesis = crate::genesis::public_testnet_v1::genesis().unwrap();
        let mut state = BranchState::genesis(&genesis).unwrap();
        let mut nullifiers = BTreeSet::new();
        let mut effects = BTreeSet::new();
        for i in (0..130_u16).rev() {
            state.nullifiers.insert(set_key(i)).unwrap();
            nullifiers.insert(set_key(i));
            if i % 2 == 0 {
                state.effects.insert(set_key(i)).unwrap();
                effects.insert(set_key(i));
            }
        }
        let nf = hash_stream(
            "SilkNode-F0-NF",
            &state.domain,
            nullifiers.len(),
            nullifiers.iter().map(|key| key.as_slice()),
        );
        let ef = hash_stream(
            "SilkNode-F0-EF",
            &state.domain,
            effects.len(),
            effects.iter().map(|key| key.as_slice()),
        );
        let rh = hash_stream(
            "SilkNode-F0-recovery-history",
            &state.domain,
            0,
            std::iter::empty(),
        );
        let pr = hash_stream(
            "SilkNode-F0-public-rewards",
            &state.domain,
            0,
            std::iter::empty(),
        );
        let expected = domain_hash(
            "SilkNode-F0-state",
            &[
                &state.domain,
                &state.root(),
                &state.leaves().to_le_bytes(),
                &nf,
                &ef,
                &state.pool.to_le_bytes(),
                &state.burned.to_le_bytes(),
                &rh,
                &pr,
                &state.issued.to_le_bytes(),
            ],
        );
        assert_eq!(state.hash_state(), expected);
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic set hash serializer")
            .unwrap();
        let retained = state.retain_ledger(&mut store, &budget).unwrap();
        assert!(
            retained
                .retained_set_pages()
                .iter()
                .all(|pages| pages.len() > 1)
        );
        assert_eq!(
            retained.hash_state_checked(Some(&budget)).unwrap(),
            expected
        );
        let restored = retained.materialize_ledger(Some(&budget)).unwrap();
        assert!(restored.retained_set_pages().iter().all(Vec::is_empty));
        for i in 0..132_u16 {
            assert_eq!(
                state.contains_nullifier(&set_key(i)),
                nullifiers.contains(&set_key(i))
            );
            assert_eq!(
                state.contains_effect(&set_key(i)),
                effects.contains(&set_key(i))
            );
            assert_eq!(
                restored.contains_nullifier(&set_key(i)),
                nullifiers.contains(&set_key(i))
            );
            assert_eq!(
                restored.contains_effect(&set_key(i)),
                effects.contains(&set_key(i))
            );
        }
    }

    #[test]
    fn paged_ledger_set_forward_and_rollback_delta_bytes_match_btree() {
        let genesis = crate::genesis::public_testnet_v1::genesis().unwrap();
        let mut prior = BranchState::genesis(&genesis).unwrap();
        let mut old_nf = BTreeSet::new();
        let mut old_ef = BTreeSet::new();
        for i in 0..128_u16 {
            prior.nullifiers.insert(set_key(i * 2)).unwrap();
            old_nf.insert(set_key(i * 2));
            if i < 64 {
                prior.effects.insert(set_key(i * 2)).unwrap();
                old_ef.insert(set_key(i * 2));
            }
        }
        prior.state_digest = prior.hash_state();
        let before = prior.manifest();
        let mut next = prior.clone();
        let mut new_nf = old_nf.clone();
        let mut new_ef = old_ef.clone();
        for i in [1, 31, 127, 255, 257] {
            next.nullifiers.insert(set_key(i)).unwrap();
            new_nf.insert(set_key(i));
            next.effects.insert(set_key(i)).unwrap();
            new_ef.insert(set_key(i));
        }
        for label in 1..=8_u8 {
            next.executed
                .push(VertexId::from_bytes([label; 32]))
                .unwrap();
            next.rewards.push([label; 112]).unwrap();
        }
        next.checkpoint_id = [9; 32];
        next.state_digest = next.hash_state();
        let outcomes = [EffectOutcome::Accepted, EffectOutcome::Conflict];
        let mut literal = Vec::from(b"SNF04DL1\0\0\0\0\0\0\0\0".as_slice());
        literal.extend_from_slice(&prior.checkpoint_id);
        literal.extend_from_slice(&next.checkpoint_id);
        literal.extend_from_slice(&2_u32.to_le_bytes());
        literal.extend_from_slice(&[0, 3]);
        for (current, old) in [(&new_nf, &old_nf), (&new_ef, &old_ef)] {
            let added = current.difference(old).collect::<Vec<_>>();
            literal.extend_from_slice(&u32::try_from(added.len()).unwrap().to_le_bytes());
            for key in added {
                literal.extend_from_slice(key);
            }
        }
        literal.extend_from_slice(&0_u32.to_le_bytes()); // no new recovery rows
        for row in next.rewards.iter() {
            literal.extend_from_slice(row);
        }
        assert_eq!(next.delta(&prior, &outcomes, false).unwrap(), literal);
        let mut rollback = Vec::from(b"SNF04DL1\x01\0\0\0\0\0\0\0".as_slice());
        rollback.extend_from_slice(&next.checkpoint_id);
        rollback.extend_from_slice(&prior.checkpoint_id);
        rollback.extend_from_slice(&0_u32.to_le_bytes());
        for state in [&next, &prior] {
            let manifest = state.manifest();
            rollback.extend_from_slice(&u32::try_from(manifest.len()).unwrap().to_le_bytes());
            rollback.extend_from_slice(&manifest);
        }
        assert_eq!(prior.delta(&next, &[], true).unwrap(), rollback);
        assert_eq!(prior.manifest(), before);
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = crate::budget::JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic set delta serializer")
            .unwrap();
        let stored_prior = prior.retain_ledger(&mut store, &budget).unwrap();
        let stored_next = next.retain_ledger(&mut store, &budget).unwrap();
        assert_eq!(
            stored_next
                .delta_checked(&stored_prior, &outcomes, false, Some(&budget))
                .unwrap(),
            literal
        );
        assert_eq!(
            stored_prior
                .delta_checked(&stored_next, &[], true, Some(&budget))
                .unwrap(),
            rollback
        );
        assert_eq!(stored_prior.manifest(), before);
        let restored = prior.clone();
        assert_eq!(restored.manifest(), before);
        assert_eq!(restored.hash_state(), prior.hash_state());
        assert!(!restored.contains_nullifier(&set_key(31)));
        assert!(!restored.contains_effect(&set_key(31)));
    }

    #[test]
    fn exact_cut_eligibility_boundaries() {
        for j in [1, 127, 128, 129, 256, 384] {
            assert_eq!(eligible_cut_index(j), 0);
        }
        for j in [385, 386, 512] {
            assert_eq!(eligible_cut_index(j), 1);
        }
        assert_eq!(eligible_cut_index(513), 2);
    }
    #[test]
    fn streamed_hash_matches_literal_full_count_prefixed_bytes() {
        let n = [3; 32];
        let a = [4; 32];
        let b = [5; 32];
        assert_eq!(
            hash_stream(
                "SilkNode-F0-NF",
                &n,
                2,
                [a.as_slice(), b.as_slice()].into_iter()
            ),
            domain_hash("SilkNode-F0-NF", &[&n, &2_u64.to_le_bytes(), &a, &b])
        );
    }
}
