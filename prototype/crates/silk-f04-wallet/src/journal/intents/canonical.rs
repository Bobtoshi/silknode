//! Opt-in trusted local wallet adapter; no secret is passed to a node endpoint.
//!
//! The immutable node borrow fixes a complete snapshot throughout each operation.
use super::{
    Digest, Error, IntentJournal, IntentReceipt, IntentStatus, Result, SaplingParameters,
    SelectedInput, SpendContext, WalletKey, context_bytes,
};
use silk_f04_node::{
    node::Node,
    scanner::{
        CompleteScan, IncomingNote, MAX_OUTPUTS, NoteStatus, OutgoingNote, RecoveredNote, scan,
        scan_incoming, scan_outgoing, visit, visit_incoming, visit_outgoing, witness_at_cut,
    },
    state::BranchState,
};

#[cfg(test)]
#[path = "../../../../silk-f04-node/tests/common/mod.rs"]
mod node_fixture;

#[cfg(test)]
mod reorg_tests;
#[cfg(test)]
mod runtime_tests;

/// Complete wallet-private incoming view, not a network response or finality claim.
pub struct Inventory {
    /// Locally retained source identity, not peer authority.
    pub local_head: Digest,
    /// Exact complete source checkpoint and eligible-cut binding.
    pub context: SpendContext,
    /// All owned positioned notes, including zero, spent and immature occurrences.
    pub notes: Vec<RecoveredNote>,
}

/// Complete receive-only local view: no nullifiers or spendable-balance assertion.
pub struct IncomingInventory {
    /// Independently retained local source identity.
    pub local_head: Digest,
    /// Complete checkpoint/cut binding, not finality.
    pub context: SpendContext,
    /// All locally decrypted received occurrences, including possibly spent ones.
    pub notes: Vec<IncomingNote>,
}
/// Complete outgoing ordinary-effect view. Genesis has no outgoing cv linkage.
pub struct OutgoingInventory {
    /// Independently retained local source identity.
    pub local_head: Digest,
    /// Complete checkpoint/cut binding, not finality.
    pub context: SpendContext,
    /// Decrypted outputs, INCLUDING change/self-payments; not additive balance.
    pub notes: Vec<OutgoingNote>,
}

/// Complete local visitor walk bound to one immutable, ready node snapshot.
///
/// The sink must stage its own effects until this receipt is returned. This is
/// neither a peer proof nor a durable wallet update or process-isolation boundary.
pub struct ScanReceipt {
    /// Exact local source identity.
    pub local_head: Digest,
    /// Complete checkpoint and eligible-cut binding.
    pub context: SpendContext,
    /// Completion/counts, produced only after the whole walk and sink succeed.
    pub walk: CompleteScan,
}

/// Receive-only stream without a spending/full-view key or accumulated inventory.
/// Sink errors use the node scanner's error type; all sink effects are provisional.
/// # Errors
/// Refuses incomplete/foreign state, horizon, invalid recovery or sink failure.
pub fn visit_incoming_from_node(
    node: &Node,
    domain: Digest,
    ivk: &sapling_crypto::keys::PreparedIncomingViewingKey,
    sink: impl FnMut(IncomingNote) -> silk_f04_node::Result<()>,
) -> Result<ScanReceipt> {
    let snapshot = Snapshot::for_domain(node, domain)?;
    let walk = visit_incoming(snapshot.state, ivk, sink)
        .map_err(|_| Error::Unavailable("complete incoming-only visitor scan"))?;
    Ok(snapshot.scan_receipt(walk))
}

/// Full-view stream requiring no spending key. Observations are wallet-private.
/// Sink errors use the node scanner's error type; publish only after success.
/// # Errors
/// Refuses incomplete/foreign state, horizon, invalid recovery or sink failure.
pub fn visit_from_node(
    node: &Node,
    domain: Digest,
    fvk: &sapling_crypto::keys::FullViewingKey,
    sink: impl FnMut(RecoveredNote) -> silk_f04_node::Result<()>,
) -> Result<ScanReceipt> {
    let snapshot = Snapshot::for_domain(node, domain)?;
    let walk = visit(snapshot.state, fvk, sink)
        .map_err(|_| Error::Unavailable("complete full-view visitor scan"))?;
    Ok(snapshot.scan_receipt(walk))
}

/// Outgoing-only stream requiring no incoming, full-view or spending key.
/// Change/self-payments remain included; this is not additive incoming balance.
/// # Errors
/// Refuses incomplete/foreign state, horizon, invalid linkage or sink failure.
pub fn visit_outgoing_from_node(
    node: &Node,
    domain: Digest,
    ovk: &sapling_crypto::keys::OutgoingViewingKey,
    sink: impl FnMut(OutgoingNote) -> silk_f04_node::Result<()>,
) -> Result<ScanReceipt> {
    let snapshot = Snapshot::for_domain(node, domain)?;
    let walk = visit_outgoing(snapshot.state, ovk, sink)
        .map_err(|_| Error::Unavailable("complete outgoing visitor scan"))?;
    Ok(snapshot.scan_receipt(walk))
}

/// Receive-only local adapter; no spending or full-view key is required.
/// # Errors
/// Refuses incomplete/foreign state, scan horizon or malformed recovery data.
pub fn incoming_from_node(
    node: &Node,
    domain: Digest,
    ivk: &sapling_crypto::keys::PreparedIncomingViewingKey,
) -> Result<IncomingInventory> {
    let snapshot = Snapshot::for_domain(node, domain)?;
    let notes = scan_incoming(snapshot.state, ivk)
        .map_err(|_| Error::Unavailable("complete incoming-only scan"))?;
    Ok(IncomingInventory {
        local_head: snapshot.local_head,
        context: snapshot.context,
        notes,
    })
}

/// Reversible canonical observation. Never clears the durable exposure latch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    /// No signed output has been made available by this intent.
    Unexposed,
    /// This saved economic effect is accepted on this complete snapshot.
    AcceptedEffect,
    /// The effect is absent and at least one signed nullifier is consumed.
    ConflictingConsumption,
    /// Neither the saved effect nor either signed nullifier is present.
    Unresolved,
}

struct Snapshot<'node> {
    state: &'node BranchState,
    local_head: Digest,
    context: SpendContext,
}

/// Opaque borrowed authority from one complete, READY local node. Only immutable
/// derived state crosses a scoped wallet worker; the node/RandomX owner does not.
/// The borrow prevents source mutation until the worker and view are finished.
/// Not serializable, a peer snapshot, finality or an independent custody claim.
pub struct ReadyWalletView<'node>(Snapshot<'node>);
impl<'node> ReadyWalletView<'node> {
    /// Derive authority from the existing complete local-node checks.
    /// # Errors
    /// Refuses incomplete state, scan horizon or uncertain local-head continuity.
    pub fn from_node(node: &'node Node) -> Result<Self> {
        Snapshot::for_domain(node, node.genesis().domain()).map(Self)
    }
}

impl<'node> Snapshot<'node> {
    const fn scan_receipt(&self, walk: CompleteScan) -> ScanReceipt {
        ScanReceipt {
            local_head: self.local_head,
            context: self.context,
            walk,
        }
    }
    fn new(node: &'node Node, key: &WalletKey) -> Result<Self> {
        Self::for_domain(node, key.domain)
    }
    fn for_domain(node: &'node Node, domain: Digest) -> Result<Self> {
        let state = node
            .state()
            .map_err(|_| Error::Unavailable("complete canonical node state"))?;
        if node.genesis().domain() != domain {
            return Err(Error::Unavailable("wallet/node domain mismatch"));
        }
        if state.recovery().len() > MAX_OUTPUTS {
            return Err(Error::Unavailable("complete wallet scan horizon"));
        }
        let cut = state.eligible_cut();
        Ok(Self {
            state,
            local_head: node
                .local_head()
                .map_err(|_| Error::Unavailable("canonical node pin"))?,
            context: SpendContext {
                checkpoint_index: state.checkpoint_index(),
                checkpoint: state.checkpoint_id(),
                state: state.digest(),
                prefix: state.prefix_commitment(),
                cut: cut.reference(domain),
                cut_leaves: cut.leaves,
            },
        })
    }
    fn inventory(&self, key: &WalletKey) -> Result<Inventory> {
        let viewing = key.key.to_diversifiable_full_viewing_key();
        // This is a local library call, not a selected-note/viewing-key RPC.
        let notes = scan(self.state, viewing.fvk())
            .map_err(|_| Error::Unavailable("complete canonical recovery scan"))?;
        Ok(Inventory {
            local_head: self.local_head,
            context: self.context,
            notes,
        })
    }
    fn inputs(&self, notes: &[RecoveredNote], positions: &[u64]) -> Result<Vec<SelectedInput>> {
        positions
            .iter()
            .map(|position| {
                let note = notes
                    .iter()
                    .find(|n| n.position == *position && n.status == NoteStatus::SpendableAtCut)
                    .ok_or(Error::Unavailable(
                        "reserved input no longer canonically spendable",
                    ))?;
                let path = witness_at_cut(self.state, self.state.eligible_cut(), *position)
                    .map_err(|_| Error::Unavailable("complete canonical witness"))?;
                Ok(SelectedInput {
                    note: note.note.clone(),
                    path,
                })
            })
            .collect()
    }
    fn selected_inputs(&self, key: &WalletKey, positions: &[u64]) -> Result<Vec<SelectedInput>> {
        if positions.is_empty()
            || positions.len() > 2
            || (positions.len() == 2 && positions[0] == positions[1])
        {
            return Err(Error::Unavailable("one or two distinct input positions"));
        }
        let mut selected = Vec::with_capacity(2);
        let _complete = visit(
            self.state,
            key.key.to_diversifiable_full_viewing_key().fvk(),
            |note| {
                if positions.contains(&note.position) {
                    selected.push(note);
                }
                Ok(())
            },
        )
        .map_err(|_| Error::Unavailable("complete selected-input scan"))?;
        self.inputs(&selected, positions)
    }
}

impl WalletKey {
    /// Full locally verified genesis-to-current incoming inventory. A partial,
    /// unavailable or foreign node is an error, never an empty wallet balance.
    /// This contains private note plaintext; keep it in the local wallet domain.
    /// # Errors
    /// Refuses unavailable state, wrong domain, scan horizon or decoding failures.
    pub fn inventory_from_node(&self, node: &Node) -> Result<Inventory> {
        Snapshot::new(node, self)?.inventory(self)
    }
    /// Full-range outgoing recovery with this wallet's outgoing viewing key.
    /// Includes change and self-payment; never add it to incoming-note balance.
    /// # Errors
    /// Refuses incomplete/foreign state, horizon or broken accepted-output linkage.
    pub fn outgoing_from_node(&self, node: &Node) -> Result<OutgoingInventory> {
        let snapshot = Snapshot::new(node, self)?;
        let notes = scan_outgoing(
            snapshot.state,
            &self.key.to_diversifiable_full_viewing_key().fvk().ovk,
        )
        .map_err(|_| Error::Unavailable("complete outgoing scan"))?;
        Ok(OutgoingInventory {
            local_head: snapshot.local_head,
            context: snapshot.context,
            notes,
        })
    }
}

impl IntentJournal<'_, '_> {
    /// Select at most two mature unspent owned occurrences from a complete local
    /// snapshot, reconstruct their witnesses, then durably reserve before proving.
    /// Prefer the smallest sufficient single input, otherwise the least-total pair.
    /// # Errors
    /// Refuses unavailable history, another intent, insufficient two-note funding,
    /// invalid recipient/value or any journal publication failure.
    pub fn reserve_from_node(
        &mut self,
        node: &Node,
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_node(node, recipient, value, false)
    }
    /// Explicitly reserve a distinct subsequent payment. All historical exposed
    /// positive inputs remain excluded, including ones made unspent by a reorg.
    /// This neither retries nor cancels any previous payment.
    /// # Errors
    /// Refuses no prior exposure, insufficient nonreserved funding or `reserve_from_node` errors.
    pub fn reserve_distinct_from_node(
        &mut self,
        node: &Node,
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_node(node, recipient, value, true)
    }
    /// The same fresh-payment reservation over a scoped immutable READY view.
    /// No input selection, scan or witness is delegated to a peer.
    /// # Errors
    /// Same refusals as `reserve_from_node`, including a foreign wallet domain.
    pub fn reserve_from_view(
        &mut self,
        view: &ReadyWalletView<'_>,
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_snapshot(&view.0, recipient, value, false)
    }
    /// Explicit DISTINCT payment, preserving every historical exposure exclusion.
    /// # Errors
    /// Same refusals as `reserve_distinct_from_node`; never an automatic retry.
    pub fn reserve_distinct_from_view(
        &mut self,
        view: &ReadyWalletView<'_>,
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_snapshot(&view.0, recipient, value, true)
    }
    fn reserve_node(
        &mut self,
        node: &Node,
        recipient: &str,
        value: u64,
        distinct: bool,
    ) -> Result<IntentReceipt> {
        let snapshot = Snapshot::new(node, self.journal.key)?;
        self.reserve_snapshot(&snapshot, recipient, value, distinct)
    }
    fn reserve_snapshot(
        &mut self,
        snapshot: &Snapshot<'_>,
        recipient: &str,
        value: u64,
        distinct: bool,
    ) -> Result<IntentReceipt> {
        self.current()?;
        if snapshot.context.cut.domain != self.journal.key.domain {
            return Err(Error::Unavailable("wallet/node domain mismatch"));
        }
        let permitted = if distinct {
            self.state.status == IntentStatus::MayHaveEscaped
        } else {
            matches!(
                self.state.status,
                IntentStatus::Empty | IntentStatus::CancelledBeforeRelease
            )
        };
        if !permitted {
            return Err(Error::Unavailable("payment already reserved or exposed"));
        }
        // At the maximum horizon, exactly 1,665,536 requested candidate bytes,
        // not 104,096 retained plaintext notes and their 512-byte memos.
        let mut funding = Vec::new();
        funding
            .try_reserve_exact(snapshot.state.recovery().len())
            .map_err(|_| Error::Unavailable("bounded funding buffer"))?;
        let _complete = visit(
            snapshot.state,
            self.journal
                .key
                .key
                .to_diversifiable_full_viewing_key()
                .fvk(),
            |note| {
                if note.status == NoteStatus::SpendableAtCut
                    && !self.exposed.contains_key(&note.nullifier)
                {
                    funding.push((note.note.value().inner(), note.position));
                }
                Ok(())
            },
        )
        .map_err(|_| Error::Unavailable("complete funding scan"))?;
        let positions = select(funding, value)?;
        let inputs = snapshot.selected_inputs(self.journal.key, &positions)?;
        self.reserve_inner(snapshot.context, &inputs, recipient, value, distinct)
    }

    /// Rebuild the exact reservation from one freshly checked complete snapshot.
    /// A changed checkpoint requires explicit pre-release reconsideration; this
    /// never rewrites the reservation or silently chooses replacement inputs.
    /// # Errors
    /// Refuses changed canonical context/spentness, incomplete witnesses or proof/
    /// durable-publication failure. No signed bytes are returned from this method.
    pub fn prove_from_node(
        &mut self,
        node: &Node,
        parameters: &SaplingParameters,
    ) -> Result<IntentReceipt> {
        let snapshot = Snapshot::new(node, self.journal.key)?;
        self.prove_snapshot(&snapshot, parameters)
    }
    /// Revalidate/reconstruct/prove against the borrowed READY view while the
    /// node remains immutable on its original thread. Returns pins, not bytes.
    /// # Errors
    /// Same refusals as `prove_from_node`, including changed reservation context.
    pub fn prove_from_view(
        &mut self,
        view: &ReadyWalletView<'_>,
        parameters: &SaplingParameters,
    ) -> Result<IntentReceipt> {
        self.prove_snapshot(&view.0, parameters)
    }
    fn prove_snapshot(
        &mut self,
        snapshot: &Snapshot<'_>,
        parameters: &SaplingParameters,
    ) -> Result<IntentReceipt> {
        self.current()?;
        if snapshot.context.cut.domain != self.journal.key.domain {
            return Err(Error::Unavailable("wallet/node domain mismatch"));
        }
        if self.state.status != IntentStatus::Reserved {
            return Err(Error::Unavailable("no unexposed reserved payment"));
        }
        let plan = self.state.plan.as_ref().ok_or(Error::Authentication)?;
        if context_bytes(snapshot.context) != context_bytes(plan.context) {
            return Err(Error::Unavailable("canonical reservation context changed"));
        }
        let positions = plan
            .inputs
            .iter()
            .map(|input| input.position)
            .collect::<Vec<_>>();
        let inputs = snapshot.selected_inputs(self.journal.key, &positions)?;
        self.prove_reserved(snapshot.context, inputs, parameters)
    }

    /// Observe the internally saved effect against a complete current local state.
    /// Confirmation is reversible; all outcomes preserve `MayHaveEscaped` and
    /// neither authorize a retry nor release inputs for another payment.
    /// # Errors
    /// Refuses changed local pins or incomplete/foreign canonical state.
    pub fn observe_from_node(&mut self, node: &Node) -> Result<Observation> {
        self.current()?;
        let snapshot = Snapshot::new(node, self.journal.key)?;
        let Some(signed) = self.state.signed.as_ref() else {
            return Ok(Observation::Unexposed);
        };
        Ok(classify(
            snapshot.state.contains_effect(&signed.effect_id()),
            signed
                .nullifiers()
                .iter()
                .any(|nf| snapshot.state.contains_nullifier(nf)),
        ))
    }
}

const fn classify(effect_present: bool, any_nullifier_present: bool) -> Observation {
    if effect_present {
        Observation::AcceptedEffect
    } else if any_nullifier_present {
        Observation::ConflictingConsumption
    } else {
        Observation::Unresolved
    }
}

fn select(mut funding: Vec<(u64, u64)>, value: u64) -> Result<Vec<u64>> {
    let needed = value
        .checked_add(1)
        .filter(|v| value > 0 && *v <= super::MAX_VALUE)
        .ok_or(Error::Unavailable("payment value and fee"))?;
    funding.retain(|(amount, _)| *amount > 0 && *amount <= super::MAX_VALUE);
    funding.sort_unstable();
    if let Some((_, position)) = funding.iter().find(|(amount, _)| *amount >= needed) {
        return Ok(vec![*position]);
    }
    let (mut low, mut high) = (0, funding.len().saturating_sub(1));
    let mut best: Option<(u64, u64, u64)> = None;
    while low < high {
        let total = funding[low].0 + funding[high].0; // Each<=MAX_VALUE; sum fits u64.
        if total >= needed {
            if total <= super::MAX_VALUE && best.is_none_or(|b| total < b.0) {
                best = Some((total, funding[low].1, funding[high].1));
            }
            high -= 1;
        } else {
            low += 1;
        }
    }
    best.map(|(_, a, b)| vec![a, b]).ok_or(Error::Unavailable(
        "insufficient spendable funding within two-input limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ready_view_scoped_reservation_uses_original_node_authority() {
        let lab = tempfile::tempdir().unwrap();
        std::fs::set_permissions(lab.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = node_fixture::fixture(&[10, 20]);
        let node = Node::create(
            &lab.path().join("node"),
            lab.path(),
            fixture.genesis.clone(),
        )
        .unwrap();
        let original_head = node.local_head().unwrap();
        let mut key = WalletKey {
            domain: fixture.genesis.domain(),
            key: fixture.keys[0].clone(),
            first_use: true,
        };
        let recipient =
            silk_sapling_f04::address::encode(&key.domain, &fixture.keys[1].default_address().1);
        let (mut journal, pin) = Journal::create_with_intents(
            &lab.path().join("wallet"),
            lab.path(),
            &mut key,
            "PUBLIC SCOPED TEST PASSWORD",
        )
        .unwrap();
        let mut intents = journal.intents(pin).unwrap();
        let view = ReadyWalletView::from_node(&node).unwrap();
        let receipt = std::thread::scope(|scope| {
            scope
                .spawn(|| intents.reserve_from_view(&view, &recipient, 4))
                .join()
                .unwrap()
        })
        .unwrap();
        assert_eq!(receipt.status, IntentStatus::Reserved);
        assert_eq!(node.local_head().unwrap(), original_head);
        assert_eq!(intents.receipt().unwrap().intent_head, receipt.intent_head);
        assert!(intents.offer_saved(receipt.intent_head).is_err());
        assert!(
            intents
                .reserve_distinct_from_view(&view, &recipient, 4)
                .is_err()
        );
        assert!(intents.reserve_from_view(&view, &recipient, 4).is_err());
        intents.cancel_before_release().unwrap();

        let foreign_fixture = node_fixture::fixture(&[12]);
        let foreign = Node::create(
            &lab.path().join("foreign"),
            lab.path(),
            foreign_fixture.genesis,
        )
        .unwrap();
        let foreign_view = ReadyWalletView::from_node(&foreign).unwrap();
        let before = intents.receipt().unwrap().intent_head;
        assert!(
            intents
                .reserve_from_view(&foreign_view, &recipient, 4)
                .is_err()
        );
        assert_eq!(intents.receipt().unwrap().intent_head, before);
    }

    #[test]
    fn complete_visitors_match_collectors_and_sink_failure_is_not_completion() {
        let lab = tempfile::tempdir().unwrap();
        std::fs::set_permissions(lab.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = node_fixture::fixture_shared_key(&[6, 7, 2]);
        let node = Node::create(
            &lab.path().join("node"),
            lab.path(),
            fixture.genesis.clone(),
        )
        .unwrap();
        let key = WalletKey {
            domain: fixture.genesis.domain(),
            key: fixture.keys[0].clone(),
            first_use: true,
        };
        let viewing = key.key.to_diversifiable_full_viewing_key();
        let ivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&viewing.fvk().vk.ivk());
        let inventory = key.inventory_from_node(&node).unwrap();
        let incoming = incoming_from_node(&node, key.domain, &ivk).unwrap();
        let mut seen = 0;
        let complete = visit_from_node(&node, key.domain, viewing.fvk(), |note| {
            let prior = &inventory.notes[seen];
            assert_eq!(note.note, prior.note);
            assert_eq!(note.address, prior.address);
            assert_eq!(note.position, prior.position);
            assert_eq!(note.nullifier, prior.nullifier);
            assert_eq!(note.status, prior.status);
            assert_eq!(note.memo, prior.memo);
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((complete.walk.scanned(), complete.walk.matched()), (3, 3));
        assert_eq!(seen, 3);
        assert_eq!(complete.local_head, inventory.local_head);
        assert_eq!(
            context_bytes(complete.context),
            context_bytes(inventory.context)
        );
        seen = 0;
        let complete = visit_incoming_from_node(&node, key.domain, &ivk, |note| {
            let prior = &incoming.notes[seen];
            assert_eq!(note.note, prior.note);
            assert_eq!(note.address, prior.address);
            assert_eq!(note.position, prior.position);
            assert_eq!(note.cut_status, prior.cut_status);
            assert_eq!(note.memo, prior.memo);
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((complete.walk.scanned(), complete.walk.matched()), (3, 3));
        assert_eq!(seen, 3);
        let complete = visit_outgoing_from_node(&node, key.domain, &viewing.fvk().ovk, |_| {
            panic!("genesis is not ordinary outgoing history")
        })
        .unwrap();
        assert_eq!((complete.walk.scanned(), complete.walk.matched()), (0, 0));
        seen = 0;
        let incomplete = visit_from_node(&node, key.domain, viewing.fvk(), |_| {
            seen += 1;
            if seen == 2 {
                Err(silk_f04_node::Error::Paused("test sink full"))
            } else {
                Ok(())
            }
        });
        assert!(incomplete.is_err());
        assert_eq!(seen, 2); // A successful earlier callback is not a complete receipt.
        let incomplete = visit_incoming_from_node(&node, key.domain, &ivk, |_| {
            Err(silk_f04_node::Error::Paused("test incoming sink full"))
        });
        assert!(incomplete.is_err());
        let foreign = crate::FreshKey::generate().unwrap().bind(key.domain);
        let complete = visit_from_node(
            &node,
            key.domain,
            foreign.key.to_diversifiable_full_viewing_key().fvk(),
            |_| panic!("unrelated key must not decrypt"),
        )
        .unwrap();
        assert_eq!((complete.walk.scanned(), complete.walk.matched()), (3, 0));
        assert!(
            visit_from_node(&node, [197; 32], viewing.fvk(), |_| panic!(
                "foreign domain reached sink"
            ))
            .is_err()
        );
        let snapshot = Snapshot::new(&node, &key).unwrap();
        let selected = snapshot.selected_inputs(&key, &[2, 0]).unwrap();
        assert_eq!(selected[0].note, inventory.notes[2].note);
        assert_eq!(selected[1].note, inventory.notes[0].note);
        assert!(snapshot.selected_inputs(&key, &[0, 0]).is_err());
        assert!(snapshot.selected_inputs(&key, &[0, 1, 2]).is_err());
        assert!(snapshot.selected_inputs(&key, &[99]).is_err());
        assert_eq!(node.local_head().unwrap(), inventory.local_head);
    }

    #[test]
    fn admitted_genesis_inventory_reservation_and_exact_context() {
        let lab = tempfile::tempdir().unwrap();
        std::fs::set_permissions(lab.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = node_fixture::fixture(&[10, 20]);
        let node = Node::create(
            &lab.path().join("node"),
            lab.path(),
            fixture.genesis.clone(),
        )
        .unwrap();
        // Fresh OS-random valueless fixture key, not a production/raw import API.
        let mut key = WalletKey {
            domain: fixture.genesis.domain(),
            key: fixture.keys[0].clone(),
            first_use: true,
        };
        let inventory = key.inventory_from_node(&node).unwrap();
        assert_eq!(inventory.local_head, node.local_head().unwrap());
        assert_eq!(
            inventory.context.prefix,
            node.state().unwrap().prefix_commitment()
        );
        assert_ne!(
            inventory.context.prefix,
            node.state().unwrap().eligible_commitment()
        );
        assert_eq!(inventory.notes.len(), 1);
        assert_eq!(inventory.notes[0].position, 0);
        assert_eq!(inventory.notes[0].status, NoteStatus::SpendableAtCut);
        assert_eq!(inventory.notes[0].note.value().inner(), 10);
        let foreign = crate::FreshKey::generate().unwrap().bind([197; 32]);
        assert!(foreign.inventory_from_node(&node).is_err());
        let recipient =
            silk_sapling_f04::address::encode(&key.domain, &fixture.keys[1].default_address().1);
        let (mut journal, pin) = Journal::create_with_intents(
            &lab.path().join("wallet"),
            lab.path(),
            &mut key,
            "PUBLIC CANONICAL TEST PASSWORD",
        )
        .unwrap();
        let mut intents = journal.intents(pin).unwrap();
        assert!(intents.reserve_from_node(&node, &recipient, 10).is_err());
        let receipt = intents.reserve_from_node(&node, &recipient, 4).unwrap();
        assert_eq!(receipt.status, IntentStatus::Reserved);
        assert_eq!(
            intents.observe_from_node(&node).unwrap(),
            Observation::Unexposed
        );
        let plan = intents.state.plan.as_ref().unwrap();
        assert_eq!(
            context_bytes(plan.context),
            context_bytes(inventory.context)
        );
        assert_eq!(plan.inputs[0].nf, inventory.notes[0].nullifier);
        let snapshot = Snapshot::new(&node, intents.journal.key).unwrap();
        let inputs = snapshot.inputs(&inventory.notes, &[0]).unwrap();
        assert_eq!(
            inputs[0]
                .path
                .root(sapling_crypto::Node::from_cmu(&inputs[0].note.cmu()))
                .to_bytes(),
            plan.context.cut.root
        );
        assert!(snapshot.inputs(&inventory.notes, &[1]).is_err());
        assert!(intents.reserve_from_node(&node, &recipient, 4).is_err());
        intents.cancel_before_release().unwrap();
    }
    #[test]
    fn bounded_two_input_selection_and_effect_not_nullifier_confirmation() {
        assert_eq!(select(vec![(10, 2), (7, 1), (0, 0)], 6).unwrap(), [1]);
        assert_eq!(select(vec![(5, 1), (3, 2), (6, 3)], 7).unwrap(), [2, 1]);
        assert!(select(vec![(2, 1), (2, 2), (2, 3)], 5).is_err());
        assert!(select(vec![], 1).is_err());
        assert!(select(vec![(10, 0)], 0).is_err());
        assert!(select(vec![(super::super::MAX_VALUE, 0)], u64::MAX).is_err());
        assert_eq!(classify(false, false), Observation::Unresolved);
        assert_eq!(classify(false, true), Observation::ConflictingConsumption);
        assert_eq!(classify(true, true), Observation::AcceptedEffect);
    }
}
