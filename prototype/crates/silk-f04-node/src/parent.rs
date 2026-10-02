//! Exact candidate-parent DAA and branch-specific delayed key derivation.
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    carriage::{ParentFacts, encode_parents},
    genesis::Genesis,
    graph::DurableGraph as Graph,
    state::{BranchState, fold_j},
};
use silk_order::sg0_v1::Sg0ParentSetV1;
use silk_pow::dag_randomx_v3::dag_target_for_work_v3;
use silk_sapling_f04::codec::{carriage_hash, domain_hash};
use silk_types::VertexId;
use std::{collections::VecDeque, sync::Arc};

/// Cache complete derived prefixes, never a source chosen by checkpoint index alone.
pub(crate) struct PrefixCache {
    genesis: Arc<BranchState>,
    states: VecDeque<Arc<BranchState>>,
    domain: Digest,
}
impl PrefixCache {
    pub fn new(g: &Genesis) -> Result<Self> {
        Ok(Self {
            genesis: Arc::new(BranchState::genesis(g)?),
            states: VecDeque::new(),
            domain: g.domain(),
        })
    }
    pub fn remember(&mut self, state: Arc<BranchState>) {
        if state.checkpoint_index() == 0 {
            return;
        }
        if self
            .states
            .iter()
            .any(|s| s.checkpoint_id() == state.checkpoint_id())
        {
            return;
        }
        let charge = state.cache_charge();
        if charge > 128 * 1024 * 1024 {
            return;
        }
        while self.states.len() >= 8
            || self.states.iter().map(|s| s.cache_charge()).sum::<usize>() + charge
                > 128 * 1024 * 1024
        {
            self.states.pop_front();
        }
        self.states.push_back(state);
    }
    pub fn derive(
        &mut self,
        graph: &Graph,
        parents: &Sg0ParentSetV1,
        g: &Genesis,
        budget: &JobBudget,
    ) -> Result<ParentFacts> {
        if g.domain() != self.domain {
            return Err(Error::Unavailable("prefix-cache context"));
        }
        budget.check()?;
        let order = graph.parent_order(parents, budget)?;
        let e = order.eligible_order();
        let m = e.len();
        let mut js = Vec::with_capacity(m + 1);
        js.push(self.genesis.eligible_commitment());
        for (i, id) in e.iter().enumerate() {
            js.push(fold_j(&self.domain, js[i], i as u64 + 1, id.into_bytes()));
        }
        budget.check()?;
        let q = m.min(43);
        let mut pv = Vec::with_capacity(257 + 56 * q);
        pv.extend_from_slice(b"SNPVF001\x01\0\0\0");
        pv.extend_from_slice(&self.domain);
        pv.extend_from_slice(&g.parameters_id());
        pv.extend_from_slice(&encode_parents(parents)?);
        if let Some(selected) = order.selected_tip() {
            pv.push(1);
            pv.extend_from_slice(&selected.into_bytes());
        } else {
            pv.extend_from_slice(&[0; 33]);
        }
        pv.extend_from_slice(&(m as u64).to_le_bytes());
        pv.extend_from_slice(&order.eligible_work().to_be_bytes());
        pv.extend_from_slice(&js[m]);
        pv.push(q as u8);
        pv.extend_from_slice(&[0; 7]);
        for (t, id) in e.iter().enumerate().skip(m - q) {
            let header = graph.header(*id, g, budget)?;
            pv.extend_from_slice(&(t as u64).to_le_bytes());
            pv.extend_from_slice(&id.into_bytes());
            pv.extend_from_slice(&header.timestamp.to_le_bytes());
            pv.extend_from_slice(&header.work.to_le_bytes());
        }
        debug_assert_eq!(pv.len(), 257 + 56 * q);
        let pvid = domain_hash("SilkNode-F01-parent-view", &[&pv]);
        let tparent = parents
            .ordinary_parents()
            .iter()
            .map(|id| graph.header(*id, g, budget).map(|h| h.timestamp))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(g.timestamp());
        let tmtp = if m == 0 {
            g.timestamp()
        } else {
            mtp(graph, e, m - 1, g, budget)?
        };
        let wref = order
            .selected_tip()
            .map(|id| graph.header(id, g, budget).map(|h| h.work))
            .transpose()?
            .unwrap_or(1);
        let epoch = 1 + m as u64 / 8;
        let sample = if m < 5 {
            Sample::initial()
        } else {
            let last = m - 1;
            let n = last.min(32);
            let start = last - n;
            let observed = e[start + 1..=last].iter().try_fold(0_u128, |sum, id| {
                Ok::<_, Error>(sum + u128::from(graph.header(*id, g, budget)?.work))
            })?;
            Sample::derive(
                start as u64,
                last as u64,
                mtp(graph, e, start, g, budget)?,
                mtp(graph, e, last, g, budget)?,
                observed,
                wref,
            )?
        };
        let mut dx = Vec::with_capacity(320 + 40 * parents.ordinary_parents().len());
        dx.extend_from_slice(b"SNDXF001");
        for x in [&self.domain, &g.parameters_id(), &pvid] {
            dx.extend_from_slice(x);
        }
        dx.extend_from_slice(&g.timestamp().to_le_bytes());
        dx.push(parents.ordinary_parents().len() as u8);
        dx.extend_from_slice(&[0; 7]);
        for id in parents.ordinary_parents() {
            dx.extend_from_slice(&id.into_bytes());
            dx.extend_from_slice(&graph.header(*id, g, budget)?.timestamp.to_le_bytes());
        }
        for v in [m as u64, epoch, tmtp, tparent, wref] {
            dx.extend_from_slice(&v.to_le_bytes());
        }
        dx.extend_from_slice(&sample.intervals.to_le_bytes());
        dx.extend_from_slice(&[0; 6]);
        dx.extend_from_slice(&sample.observed.to_le_bytes());
        for v in [
            sample.start,
            sample.last,
            sample.a,
            sample.b,
            sample.raw_span,
            sample.expected,
            sample.min_span,
            sample.max_span,
            sample.span,
            sample.raw_next,
            sample.min_next,
            sample.max_next,
            sample.work,
        ] {
            dx.extend_from_slice(&v.to_le_bytes());
        }
        dx.extend_from_slice(
            &dag_target_for_work_v3(sample.work)
                .map_err(|_| Error::Invalid("DAA target"))?
                .to_be_bytes(),
        );
        debug_assert_eq!(dx.len(), 320 + 40 * parents.ordinary_parents().len());
        let daa = domain_hash("SilkNode-F01-DAA-context", &[&dx]);
        let minimum_time = tparent
            .max(tmtp)
            .checked_add(1)
            .ok_or(Error::Invalid("no representable child timestamp"))?;

        let mut source = self.genesis.clone();
        let mut selected_frontier = Vec::new();
        let latest = if m >= 48 { ((m - 16) / 32) * 4 } else { 0 };
        // Each search quantum is <=16 source candidates; each replay quantum below
        // is exactly eight positions. All quanta share this original job budget.
        for s in (4..=latest).rev().filter(|s| s % 4 == 0) {
            budget.source()?;
            budget.check()?;
            let end = s * 8;
            // A source MUST be reconstructed, including its full own ledger/cuts,
            // before any claim that it is unusable; a cache miss never skips it.
            let derived = self.reconstruct(graph, &e[..end], &js[..=end], g, budget)?;
            let mut frontier = Vec::with_capacity(4);
            for id in e[..end].iter().rev() {
                budget.probe()?;
                budget.check()?;
                let mut dominated = false;
                for tip in &frontier {
                    budget.probe()?;
                    if graph.is_ancestor(*id, *tip)? {
                        dominated = true;
                        break;
                    }
                }
                if !dominated {
                    frontier.push(*id);
                }
                // Reverse topological order: a fourth maximal member cannot be
                // removed by an earlier prefix member. The true set is then >3.
                if frontier.len() > 3 {
                    break;
                }
            }
            if frontier.is_empty() || frontier.len() > 3 {
                continue;
            }
            frontier.sort();
            let mut common = true;
            for f in &frontier {
                for p in parents.ordinary_parents() {
                    budget.probe()?;
                    if f != p && !graph.is_ancestor(*f, *p)? {
                        common = false;
                    }
                }
            }
            if common {
                source = derived;
                selected_frontier = frontier;
                break;
            }
        }
        let s = source.checkpoint_index();
        let mut source_record = [0; 184];
        source_record[..8].copy_from_slice(&s.to_le_bytes());
        source_record[8..16].copy_from_slice(&(s * 8).to_le_bytes());
        source_record[16..48].copy_from_slice(&source.checkpoint_id());
        source_record[48..80].copy_from_slice(&source.eligible_commitment());
        source_record[80] = selected_frontier.len() as u8;
        for (i, id) in selected_frontier.iter().enumerate() {
            source_record[88 + 32 * i..120 + 32 * i].copy_from_slice(&id.into_bytes());
        }
        let seed = carriage_hash(
            "SilkNode/F01-RandomX-Seed/v1",
            &[
                &self.domain,
                &g.parameters_id(),
                &g.context().bytes()[44..76],
                &g.context().bytes()[76..108],
                &s.to_be_bytes(),
                &source.checkpoint_id(),
                &source.eligible_commitment(),
            ],
        );
        let key_material = carriage_hash("SilkNode/F01-RandomX-Key/v1", &[&self.domain, &seed]);
        budget.check()?;
        Ok(ParentFacts {
            source_record,
            epoch,
            daa,
            work: sample.work,
            minimum_time,
            source_index: s,
            source_checkpoint: source.checkpoint_id(),
            source_j: source.eligible_commitment(),
            seed,
            key_material,
        })
    }
    fn reconstruct(
        &mut self,
        graph: &Graph,
        ids: &[VertexId],
        js: &[Digest],
        genesis: &Genesis,
        budget: &JobBudget,
    ) -> Result<Arc<BranchState>> {
        let mut selected: Option<Arc<BranchState>> = None;
        for state in &self.states {
            if state.executed_len() <= ids.len()
                && state.eligible_commitment() == js[state.executed_len()]
                && state.executed_prefix_matches_checked(ids, Some(budget))?
                && selected
                    .as_ref()
                    .is_none_or(|selected| state.executed_len() >= selected.executed_len())
            {
                selected = Some(state.clone());
            }
        }
        let mut state = selected.unwrap_or_else(|| self.genesis.clone());
        while state.executed_len() < ids.len() {
            budget.replay()?;
            budget.check()?;
            let start = state.executed_len();
            let batch = ids[start..start + 8]
                .iter()
                .map(|id| graph.load_for_execution(*id, genesis, budget))
                .collect::<Result<Vec<_>>>()?;
            state = Arc::new(
                state
                    .execute(
                        batch
                            .iter()
                            .map(Arc::as_ref)
                            .collect::<Vec<_>>()
                            .try_into()
                            .map_err(|_| Error::Unavailable("source replay batch"))?,
                        budget,
                    )?
                    .state,
            );
            budget.check()?;
            self.remember(state.clone());
        }
        Ok(state)
    }
}

#[cfg(test)]
pub(crate) fn replay_source_for_test(
    graph: &Graph,
    genesis: &Genesis,
    ids: &[VertexId],
    budget: &JobBudget,
) -> Result<Arc<BranchState>> {
    let mut cache = PrefixCache::new(genesis)?;
    let mut js = vec![cache.genesis.eligible_commitment()];
    for (i, id) in ids.iter().enumerate() {
        js.push(fold_j(
            &genesis.domain(),
            js[i],
            i as u64 + 1,
            id.into_bytes(),
        ));
    }
    cache.reconstruct(graph, ids, &js, genesis, budget)
}

fn mtp(
    graph: &Graph,
    e: &[VertexId],
    i: usize,
    genesis: &Genesis,
    budget: &JobBudget,
) -> Result<u64> {
    let mut times = e[(i + 1).saturating_sub(11)..=i]
        .iter()
        .map(|id| graph.header(*id, genesis, budget).map(|h| h.timestamp))
        .collect::<Result<Vec<_>>>()?;
    times.sort_unstable();
    Ok(times[(times.len() - 1) / 2])
}
struct Sample {
    intervals: u16,
    observed: u128,
    start: u64,
    last: u64,
    a: u64,
    b: u64,
    raw_span: u64,
    expected: u64,
    min_span: u64,
    max_span: u64,
    span: u64,
    raw_next: u64,
    min_next: u64,
    max_next: u64,
    work: u64,
}
impl Sample {
    fn initial() -> Self {
        Self {
            intervals: 0,
            observed: 0,
            start: 0,
            last: 0,
            a: 0,
            b: 0,
            raw_span: 0,
            expected: 0,
            min_span: 0,
            max_span: 0,
            span: 0,
            raw_next: 1,
            min_next: 1,
            max_next: 1,
            work: 1,
        }
    }
    fn derive(start: u64, last: u64, a: u64, b: u64, observed: u128, wref: u64) -> Result<Self> {
        let n = last
            .checked_sub(start)
            .filter(|n| (4..=32).contains(n))
            .ok_or(Error::Invalid("DAA sample interval"))?;
        if !(1..=1_000_000).contains(&wref)
            || observed < u128::from(n)
            || observed > u128::from(n) * 1_000_000
        {
            return Err(Error::Invalid("DAA observed work"));
        }
        let raw_span = b.saturating_sub(a).max(1);
        let expected = 10 * n;
        let min_span = expected.div_ceil(4);
        let max_span = expected * 4;
        let span = raw_span.clamp(min_span, max_span);
        let numerator = observed * 10;
        let raw_next = u64::try_from(
            numerator / u128::from(span) + u128::from(numerator % u128::from(span) != 0),
        )
        .map_err(|_| Error::Invalid("DAA arithmetic"))?;
        let min_next = wref.div_ceil(2).max(1);
        let max_next = (2 * wref).min(1_000_000);
        let work = raw_next.clamp(min_next, max_next);
        Ok(Self {
            intervals: n as u16,
            observed,
            start,
            last,
            a,
            b,
            raw_span,
            expected,
            min_span,
            max_span,
            span,
            raw_next,
            min_next,
            max_next,
            work,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_floor_ceil_signed_span_and_work_bounds() {
        let initial = Sample::initial();
        assert_eq!(
            (initial.observed, initial.raw_span, initial.work),
            (0, 0, 1)
        );
        let s = Sample::derive(0, 4, 10, 50, 4, 1).unwrap();
        assert_eq!(s.work, 1);
        let s = Sample::derive(0, 4, 50, 10, 12, 3).unwrap();
        assert_eq!((s.raw_span, s.span, s.raw_next, s.work), (1, 10, 12, 6));
        let s = Sample::derive(0, 32, 1, u64::MAX, 32, 3).unwrap();
        assert_eq!((s.span, s.min_next, s.work), (1280, 2, 2));
        let s = Sample::derive(0, 32, 20, 20, 32_000_000, 1_000_000).unwrap();
        assert_eq!(s.work, 1_000_000);
    }
}
