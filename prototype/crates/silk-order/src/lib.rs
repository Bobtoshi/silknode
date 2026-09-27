#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic cumulative-work reference ordering rooted at an authenticated
//! non-PoW genesis anchor.
//!
//! This crate is the no-value linear control required by decision D-006. The
//! external genesis anchor is not a vertex, never appears in ordered history,
//! and contributes exactly zero work. Work values and control identifiers are
//! explicit test-oracle inputs: they are not proof-of-work evidence and convey
//! no reward or issuance authority.

mod gate2_dag;
pub mod sg0_v1;

pub use gate2_dag::{
    Gate2DagError, SyntheticGate2DagAssembly, SyntheticGate2DagBodyPin, SyntheticGate2DagBodyStore,
    SyntheticGate2DagSelectedAssembly, SyntheticGate2DagStorePin,
};

use silk_bootstrap::VerifiedFirstChildAnchorReference;
use silk_types::{ChainDomain, GenesisId, Hash32, ManifestHash, ProfileDomain};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

/// A synthetic identifier used only by the no-value linear ordering oracle.
///
/// This is deliberately distinct from `silk_types::VertexId`. Constructing it
/// from a hash does not prove that a vertex exists or that any proof of work is
/// valid. A future mined-vertex contract must replace this test boundary rather
/// than reinterpret it as production consensus evidence.
///
/// ```compile_fail
/// use silk_order::LinearControlVertexId;
/// use silk_types::GenesisId;
///
/// let _: LinearControlVertexId = GenesisId::ZERO.into();
/// ```
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LinearControlVertexId(Hash32);

impl LinearControlVertexId {
    /// Creates a synthetic control identifier from a test-oracle hash.
    #[must_use]
    pub const fn from_test_oracle_hash(hash: Hash32) -> Self {
        Self(hash)
    }

    /// Returns the underlying test-oracle hash.
    #[must_use]
    pub const fn test_oracle_hash(self) -> Hash32 {
        self.0
    }
}

impl fmt::Display for LinearControlVertexId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AnchorContext {
    genesis_id: GenesisId,
    chain_domain: ChainDomain,
    protocol_manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
}

impl AnchorContext {
    const fn from_verified(reference: &VerifiedFirstChildAnchorReference) -> Self {
        Self {
            genesis_id: reference.genesis_id(),
            chain_domain: reference.chain_domain(),
            protocol_manifest_hash: reference.protocol_manifest_hash(),
            profile_domain: reference.profile_domain(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinearParentKind {
    Anchor(AnchorContext),
    Vertex(LinearControlVertexId),
}

/// The single parent of a no-value linear-control vertex.
///
/// An anchor parent can be constructed only from an authenticated bootstrap
/// reference. A vertex parent names another synthetic control vertex. The
/// private representation prevents parentless, multi-parent, and raw-genesis
/// states from entering the typed ordering API.
///
/// ```compile_fail
/// use silk_bootstrap::UnverifiedFirstChildAnchorReference;
/// use silk_order::LinearParent;
///
/// fn unverified_is_not_an_anchor(candidate: &UnverifiedFirstChildAnchorReference) {
///     let _ = LinearParent::anchor(candidate);
/// }
/// ```
///
/// ```compile_fail
/// use silk_order::LinearParent;
/// use silk_types::GenesisId;
///
/// let _ = LinearParent::vertex(GenesisId::ZERO);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinearParent {
    kind: LinearParentKind,
}

impl LinearParent {
    /// Roots a first-layer control vertex at an authenticated genesis anchor.
    #[must_use]
    pub const fn anchor(reference: &VerifiedFirstChildAnchorReference) -> Self {
        Self::from_anchor_context(AnchorContext::from_verified(reference))
    }

    /// Names an ordinary synthetic control vertex as the single parent.
    #[must_use]
    pub const fn vertex(id: LinearControlVertexId) -> Self {
        Self {
            kind: LinearParentKind::Vertex(id),
        }
    }

    const fn from_anchor_context(context: AnchorContext) -> Self {
        Self {
            kind: LinearParentKind::Anchor(context),
        }
    }
}

/// A candidate vertex for the no-value linear control history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearVertex {
    /// Synthetic control identifier; this is not a validated `VertexId`.
    pub id: LinearControlVertexId,
    /// Exactly one typed parent: authenticated anchor or control vertex.
    pub parent: LinearParent,
    /// Positive test-oracle work used only to exercise deterministic ordering.
    pub declared_test_work: u128,
    /// Whether the complete candidate body is locally available in the oracle.
    pub body_available: bool,
}

/// The selected no-value control history, ordered from first child through tip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearHistory {
    /// Selected control IDs in execution order; the anchor is never included.
    pub vertices: Vec<LinearControlVertexId>,
    /// Checked sum of ordinary control-vertex work; anchor contribution is zero.
    pub cumulative_test_work: u128,
}

/// Deterministic failures in the control ordering input.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OrderError {
    /// A synthetic candidate reused the exact genesis identifier bytes.
    #[error("vertex {0} collides with the genesis anchor id")]
    AnchorIdCollision(LinearControlVertexId),
    /// A vertex-parent slot reused genesis bytes instead of the anchor variant.
    #[error("vertex {0} encodes the genesis anchor as an ordinary parent")]
    RawAnchorParent(LinearControlVertexId),
    /// A first-layer candidate names a different authenticated initial context.
    #[error("vertex {0} names the wrong genesis anchor")]
    WrongAnchor(LinearControlVertexId),
    /// Test-oracle work must be strictly positive for every ordinary candidate.
    #[error("vertex {0} declares zero test work")]
    ZeroWork(LinearControlVertexId),
    /// The map key and synthetic control identifier disagree.
    #[error("vertex map key does not match its declared control id")]
    KeyMismatch,
    /// A parent walk encountered a cycle.
    #[error("vertex ancestry contains a cycle at {0}")]
    Cycle(LinearControlVertexId),
    /// Cumulative test work overflowed its control integer.
    #[error("cumulative test work overflow")]
    WorkOverflow,
}

impl OrderError {
    /// Returns the stable language-neutral code used by differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AnchorIdCollision(_) => "order.anchor_id_collision",
            Self::RawAnchorParent(_) => "order.raw_anchor_parent",
            Self::WrongAnchor(_) => "order.wrong_anchor",
            Self::ZeroWork(_) => "order.zero_work",
            Self::KeyMismatch => "order.key_mismatch",
            Self::Cycle(_) => "order.cycle",
            Self::WorkOverflow => "order.work_overflow",
        }
    }
}

/// Selects the available ordinary history with greatest cumulative test work.
///
/// The authenticated anchor seeds an empty history with zero work. Missing or
/// unavailable ordinary ancestors leave a candidate pending, so neither that
/// candidate nor its descendants receive control weight. Equal-work tips are
/// resolved by the lexicographically larger control ID, making insertion and
/// arrival order irrelevant.
///
/// This function does not validate proof of work, calculate work from a target,
/// or authorize rewards or issuance.
///
/// ```compile_fail
/// use silk_genesis::GenesisObjectPin;
/// use silk_order::{LinearControlVertexId, LinearVertex, cumulative_work_order};
/// use std::collections::BTreeMap;
///
/// fn caller_pin_cannot_root_order(
///     caller_pin: &GenesisObjectPin,
///     vertices: &BTreeMap<LinearControlVertexId, LinearVertex>,
/// ) {
///     let _ = cumulative_work_order(caller_pin, vertices);
/// }
/// ```
///
/// # Errors
///
/// Returns [`OrderError`] when a known vertex is structurally invalid, names a
/// different authenticated anchor, contains a cycle, or overflows checked test
/// work.
pub fn cumulative_work_order(
    anchor: &VerifiedFirstChildAnchorReference,
    vertices: &BTreeMap<LinearControlVertexId, LinearVertex>,
) -> Result<LinearHistory, OrderError> {
    cumulative_work_order_for_context(AnchorContext::from_verified(anchor), vertices)
}

fn cumulative_work_order_for_context(
    anchor: AnchorContext,
    vertices: &BTreeMap<LinearControlVertexId, LinearVertex>,
) -> Result<LinearHistory, OrderError> {
    for (key, vertex) in vertices {
        if *key != vertex.id {
            return Err(OrderError::KeyMismatch);
        }
        if vertex.id.0.as_bytes() == anchor.genesis_id.as_bytes() {
            return Err(OrderError::AnchorIdCollision(vertex.id));
        }
        if vertex.declared_test_work == 0 {
            return Err(OrderError::ZeroWork(vertex.id));
        }
        match vertex.parent.kind {
            LinearParentKind::Anchor(actual) => {
                if actual != anchor {
                    return Err(OrderError::WrongAnchor(vertex.id));
                }
            }
            LinearParentKind::Vertex(parent) => {
                if parent.0.as_bytes() == anchor.genesis_id.as_bytes() {
                    return Err(OrderError::RawAnchorParent(vertex.id));
                }
            }
        }
    }

    let mut best_path = Vec::new();
    let mut best_work = 0_u128;
    let mut best_tip = None;

    for candidate in vertices.keys().copied() {
        let Some((path, work)) = resolved_path(anchor, candidate, vertices)? else {
            continue;
        };
        if work > best_work || (work == best_work && best_tip.is_none_or(|tip| candidate > tip)) {
            best_path = path;
            best_work = work;
            best_tip = Some(candidate);
        }
    }

    Ok(LinearHistory {
        vertices: best_path,
        cumulative_test_work: best_work,
    })
}

fn resolved_path(
    anchor: AnchorContext,
    tip: LinearControlVertexId,
    vertices: &BTreeMap<LinearControlVertexId, LinearVertex>,
) -> Result<Option<(Vec<LinearControlVertexId>, u128)>, OrderError> {
    let mut reverse_path = Vec::new();
    let mut reverse_work = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = tip;
    let mut fully_available = true;

    loop {
        if !seen.insert(cursor) {
            return Err(OrderError::Cycle(cursor));
        }
        let Some(vertex) = vertices.get(&cursor) else {
            return Ok(None);
        };
        fully_available &= vertex.body_available;
        reverse_path.push(cursor);
        reverse_work.push(vertex.declared_test_work);

        match vertex.parent.kind {
            LinearParentKind::Anchor(actual) => {
                if actual != anchor {
                    return Err(OrderError::WrongAnchor(vertex.id));
                }
                break;
            }
            LinearParentKind::Vertex(parent) => cursor = parent,
        }
    }

    if !fully_available {
        return Ok(None);
    }
    let work = reverse_work.into_iter().try_fold(0_u128, |total, value| {
        total.checked_add(value).ok_or(OrderError::WorkOverflow)
    })?;
    reverse_path.reverse();
    Ok(Some((reverse_path, work)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32::new([byte; Hash32::LENGTH])
    }

    fn id(byte: u8) -> LinearControlVertexId {
        LinearControlVertexId::from_test_oracle_hash(hash(byte))
    }

    fn anchor(byte: u8) -> AnchorContext {
        AnchorContext {
            genesis_id: GenesisId::new(hash(byte)),
            chain_domain: ChainDomain::new(hash(byte.wrapping_add(1))),
            protocol_manifest_hash: ManifestHash::new(hash(byte.wrapping_add(2))),
            profile_domain: ProfileDomain::new(hash(byte.wrapping_add(3))),
        }
    }

    fn first(byte: u8, anchor: AnchorContext, work: u128) -> LinearVertex {
        LinearVertex {
            id: id(byte),
            parent: LinearParent::from_anchor_context(anchor),
            declared_test_work: work,
            body_available: true,
        }
    }

    fn child(byte: u8, parent: u8, work: u128) -> LinearVertex {
        LinearVertex {
            id: id(byte),
            parent: LinearParent::vertex(id(parent)),
            declared_test_work: work,
            body_available: true,
        }
    }

    fn map(
        vertices: impl IntoIterator<Item = LinearVertex>,
    ) -> BTreeMap<LinearControlVertexId, LinearVertex> {
        vertices
            .into_iter()
            .map(|vertex| (vertex.id, vertex))
            .collect()
    }

    #[test]
    fn external_anchor_seeds_empty_zero_work_history() {
        let history = cumulative_work_order_for_context(anchor(0x10), &BTreeMap::new()).unwrap();
        assert!(history.vertices.is_empty());
        assert_eq!(history.cumulative_test_work, 0);
    }

    #[test]
    fn chooses_greatest_work_without_counting_anchor() {
        let initial = anchor(0x10);
        let vertices = map([
            first(1, initial, 2),
            child(2, 1, 2),
            child(3, 2, 2),
            first(4, initial, 10),
        ]);
        let history = cumulative_work_order_for_context(initial, &vertices).unwrap();
        assert_eq!(history.vertices, vec![id(4)]);
        assert_eq!(history.cumulative_test_work, 10);
    }

    #[test]
    fn competing_first_layer_candidates_use_id_tie_break() {
        let initial = anchor(0x10);
        let vertices = map([first(2, initial, 5), first(3, initial, 5)]);
        let history = cumulative_work_order_for_context(initial, &vertices).unwrap();
        assert_eq!(history.vertices, vec![id(3)]);
        assert_eq!(history.cumulative_test_work, 5);
    }

    #[test]
    fn unavailable_or_missing_ordinary_ancestor_adds_no_weight() {
        let initial = anchor(0x10);
        let mut blocked = first(2, initial, 50);
        blocked.body_available = false;
        let vertices = map([
            blocked,
            child(3, 2, 50),
            first(4, initial, 2),
            child(5, 99, 100),
        ]);
        let history = cumulative_work_order_for_context(initial, &vertices).unwrap();
        assert_eq!(history.vertices, vec![id(4)]);
        assert_eq!(history.cumulative_test_work, 2);
    }

    #[test]
    fn rejects_wrong_anchor_before_ordering() {
        let initial = anchor(0x10);
        let vertices = map([first(1, anchor(0x20), 1)]);
        assert_eq!(
            cumulative_work_order_for_context(initial, &vertices),
            Err(OrderError::WrongAnchor(id(1)))
        );
    }

    #[test]
    fn rejects_key_mismatch_zero_work_cycle_and_overflow() {
        let initial = anchor(0x10);

        let mut mismatched = BTreeMap::new();
        mismatched.insert(id(9), first(1, initial, 1));
        assert_eq!(
            cumulative_work_order_for_context(initial, &mismatched),
            Err(OrderError::KeyMismatch)
        );

        let zero = map([first(1, initial, 0)]);
        assert_eq!(
            cumulative_work_order_for_context(initial, &zero),
            Err(OrderError::ZeroWork(id(1)))
        );

        let cycle = map([child(2, 3, 1), child(3, 2, 1)]);
        assert!(matches!(
            cumulative_work_order_for_context(initial, &cycle),
            Err(OrderError::Cycle(_))
        ));

        let mut unavailable_cycle_vertex = child(2, 3, 1);
        unavailable_cycle_vertex.body_available = false;
        let unavailable_cycle = map([unavailable_cycle_vertex, child(3, 2, 1)]);
        assert!(matches!(
            cumulative_work_order_for_context(initial, &unavailable_cycle),
            Err(OrderError::Cycle(_))
        ));

        let overflow = map([first(1, initial, u128::MAX), child(2, 1, 1)]);
        assert_eq!(
            cumulative_work_order_for_context(initial, &overflow),
            Err(OrderError::WorkOverflow)
        );
    }

    #[test]
    fn raw_genesis_bytes_cannot_masquerade_as_vertex_or_parent() {
        let initial = anchor(0x10);
        let colliding_id = LinearControlVertexId::from_test_oracle_hash(hash(0x10));
        let colliding_vertex = LinearVertex {
            id: colliding_id,
            parent: LinearParent::from_anchor_context(initial),
            declared_test_work: 1,
            body_available: true,
        };
        let vertices = map([colliding_vertex]);
        assert_eq!(
            cumulative_work_order_for_context(initial, &vertices),
            Err(OrderError::AnchorIdCollision(colliding_id))
        );

        let raw_parent = LinearVertex {
            id: id(1),
            parent: LinearParent::vertex(colliding_id),
            declared_test_work: 1,
            body_available: true,
        };
        let vertices = map([raw_parent]);
        assert_eq!(
            cumulative_work_order_for_context(initial, &vertices),
            Err(OrderError::RawAnchorParent(id(1)))
        );
    }

    #[test]
    fn public_signature_requires_authenticated_reference() {
        let _: fn(
            &VerifiedFirstChildAnchorReference,
            &BTreeMap<LinearControlVertexId, LinearVertex>,
        ) -> Result<LinearHistory, OrderError> = cumulative_work_order;
    }
}
