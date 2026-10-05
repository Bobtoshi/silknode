//! Live receiver order retention using the unchanged original SNF04OR1 record.
//! No persisted-order constructor, imported validity, or consensus format change.
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    state::BranchState,
    store::ObjectReader,
    sync::HISTORY_LIMIT_V1,
    wire::{raw_hash, u32le},
};
use silk_order::sg0_v1::Sg0OrderSnapshotV1;
use silk_types::VertexId;
use std::sync::Arc;

const HEADER: usize = 76;
/// Provisional scan data becomes usable only after complete order hashing and
/// every supplied ledger's full qualification. At most six ledgers and eight
/// selected IDs; never an importable order or a verification certificate.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct OrderInspection {
    pub count: usize,
    pub common: Vec<usize>,
    pub interval: Vec<VertexId>,
}
#[derive(Clone)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) enum CoreOrder {
    Resident(Arc<Sg0OrderSnapshotV1>),
    Retained(RetainedOrder),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_order_empty_exact_encoding_and_live_binding_horizon_refuse() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let snapshot = crate::graph::Graph::default().order(&budget).unwrap();
        let original = snapshot_bytes(&snapshot);
        assert_eq!(original.len(), HEADER);
        assert_eq!(&original[..8], b"SNF04OR1");
        assert_eq!(&original[72..], &[0; 4]);
        store
            .commit(&[&original], b"synthetic empty original order")
            .unwrap();
        let retained =
            CoreOrder::retain(&snapshot, store.object_reader().unwrap(), &budget).unwrap();
        assert!(retained.eligible(&budget).unwrap().is_empty());
        assert_eq!(retained.selected_tip(), None);
        for mutation in 0..4 {
            let mut wrong = retained.clone();
            if let CoreOrder::Retained(rows) = &mut wrong {
                match mutation {
                    0 => rows.graph[0] ^= 1,
                    1 => rows.total[0] ^= 1,
                    2 => rows.count = 1,
                    _ => rows.count = HISTORY_LIMIT_V1 + 1,
                }
            }
            assert!(wrong.bytes(&budget).is_err());
        }
    }
}
#[derive(Clone)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct RetainedOrder {
    id: Digest,
    count: usize,
    graph: Digest,
    total: Digest,
    selected: Option<VertexId>,
    reader: Arc<ObjectReader>,
}
// This encoder is byte-identical to the original node order encoder.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn snapshot_bytes(order: &Sg0OrderSnapshotV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + order.eligible_order().len() * 32);
    bytes.extend_from_slice(b"SNF04OR1");
    bytes.extend_from_slice(&order.graph_commitment().into_bytes());
    bytes.extend_from_slice(&order.total_order_commitment().into_bytes());
    bytes.extend_from_slice(
        &u32::try_from(order.eligible_order().len())
            .expect("bounded receiver-derived order length")
            .to_le_bytes(),
    );
    for id in order.eligible_order() {
        bytes.extend_from_slice(id.as_bytes());
    }
    bytes
}
impl CoreOrder {
    #[cfg(test)]
    pub(crate) fn synthetic_retained(bytes: &[u8], reader: Arc<ObjectReader>) -> Self {
        Self::Retained(RetainedOrder {
            id: raw_hash(bytes),
            count: u32le(bytes, 72).unwrap() as usize,
            graph: bytes[8..40].try_into().unwrap(),
            total: bytes[40..72].try_into().unwrap(),
            selected: None,
            reader,
        })
    }
    pub(crate) fn inspect(
        &self,
        states: &[&BranchState],
        interval_start: Option<usize>,
        budget: &JobBudget,
    ) -> Result<OrderInspection> {
        budget.check()?;
        if states.len() > 6 {
            return Err(Error::Unavailable("order comparison state bound"));
        }
        let interval_end = interval_start
            .map(|start| {
                start
                    .checked_add(8)
                    .ok_or(Error::Unavailable("order inspection interval"))
            })
            .transpose()?;
        let mut comparisons = states
            .iter()
            .map(|state| state.execution_comparison())
            .collect::<Vec<_>>();
        let mut count = 0_usize;
        let mut interval = Vec::with_capacity(if interval_start.is_some() { 8 } else { 0 });
        let mut observe = |id: VertexId| -> Result<()> {
            budget.check()?;
            for comparison in &mut comparisons {
                comparison.advance(&id, budget)?;
            }
            if interval_start
                .zip(interval_end)
                .is_some_and(|(start, end)| (start..end).contains(&count))
            {
                interval.push(id);
            }
            count += 1;
            Ok(())
        };
        match self {
            Self::Resident(order) => {
                if order.eligible_order().len() > HISTORY_LIMIT_V1
                    || order.total_order().len() > HISTORY_LIMIT_V1
                {
                    return Err(Error::Unavailable("retained order horizon"));
                }
                for id in order.eligible_order() {
                    observe(*id)?;
                }
            }
            Self::Retained(order) => {
                if order.count > HISTORY_LIMIT_V1 {
                    return Err(Error::Unavailable("retained order horizon"));
                }
                let header = order.reader.visit_order(
                    order.id,
                    HEADER + order.count * 32,
                    budget,
                    &mut |rows| {
                        for row in rows.chunks_exact(32) {
                            observe(VertexId::from_bytes(
                                row.try_into()
                                    .map_err(|_| Error::Unavailable("retained order vertex"))?,
                            ))?;
                        }
                        Ok(())
                    },
                )?;
                if header[8..40] != order.graph
                    || header[40..72] != order.total
                    || u32le(&header, 72)? as usize != order.count
                {
                    return Err(Error::Unavailable("retained order binding"));
                }
            }
        }
        let common = comparisons
            .into_iter()
            .map(|comparison| comparison.finish(budget))
            .collect::<Result<Vec<_>>>()?;
        budget.check()?;
        Ok(OrderInspection {
            count,
            common,
            interval,
        })
    }
    pub(crate) fn resident(order: Sg0OrderSnapshotV1) -> Self {
        Self::Resident(Arc::new(order))
    }
    /// Only after the original record is durable and its full order freshly derived.
    pub(crate) fn retain(
        order: &Sg0OrderSnapshotV1,
        reader: Arc<ObjectReader>,
        budget: &JobBudget,
    ) -> Result<Self> {
        budget.check()?;
        if order.eligible_order().len() > HISTORY_LIMIT_V1
            || order.total_order().len() > HISTORY_LIMIT_V1
        {
            return Err(Error::Paused("order reference horizon"));
        }
        let expected = snapshot_bytes(order);
        let retained = Self::Retained(RetainedOrder {
            id: raw_hash(&expected),
            count: order.eligible_order().len(),
            graph: order.graph_commitment().into_bytes(),
            total: order.total_order_commitment().into_bytes(),
            selected: order.selected_tip(),
            reader,
        });
        if retained.bytes(budget)? != expected {
            return Err(Error::Unavailable("live order representation mismatch"));
        }
        budget.check()?;
        Ok(retained)
    }
    /// Full hash/type/inode and exact live framing checks on every retained read.
    pub(crate) fn bytes(&self, budget: &JobBudget) -> Result<Vec<u8>> {
        budget.check()?;
        match self {
            Self::Resident(order) => Ok(snapshot_bytes(order)),
            Self::Retained(order) => {
                if order.count > HISTORY_LIMIT_V1 {
                    return Err(Error::Unavailable("retained order horizon"));
                }
                let size = HEADER + order.count * 32;
                let bytes = order.reader.order(order.id, size, budget)?;
                if bytes.len() != size
                    || bytes.get(..8) != Some(b"SNF04OR1")
                    || bytes[8..40] != order.graph
                    || bytes[40..72] != order.total
                    || u32le(&bytes, 72)? as usize != order.count
                {
                    return Err(Error::Unavailable("retained order binding"));
                }
                budget.check()?;
                Ok(bytes)
            }
        }
    }
    /// Owned operation-local IDs. The core never caches these payload vectors.
    #[cfg(test)]
    pub(crate) fn eligible(&self, budget: &JobBudget) -> Result<Vec<VertexId>> {
        let bytes = self.bytes(budget)?;
        let ids = bytes[HEADER..]
            .chunks_exact(32)
            .map(|row| {
                Ok(VertexId::from_bytes(row.try_into().map_err(|_| {
                    Error::Unavailable("retained order vertex")
                })?))
            })
            .collect::<Result<Vec<_>>>()?;
        budget.check()?;
        Ok(ids)
    }
    pub(crate) fn selected_tip(&self) -> Option<VertexId> {
        match self {
            Self::Resident(order) => order.selected_tip(),
            Self::Retained(order) => order.selected,
        }
    }
    #[cfg(test)]
    pub(crate) fn retained_id(&self) -> Option<Digest> {
        match self {
            Self::Resident(_) => None,
            Self::Retained(order) => Some(order.id),
        }
    }
}
