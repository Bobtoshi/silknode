//! Local wallet/scanner module over an authenticated complete canonical snapshot.
//! Viewing/spending material never enters the node admission or work APIs.
use crate::{
    Digest, Error, Result,
    state::{BranchState, Cut},
};
use sapling_crypto::{
    CommitmentTree, IncrementalWitness, MerklePath, Node, Note, PaymentAddress,
    keys::{FullViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey},
};
use silk_sapling_f04::wallet::RecoveryOutput;

/// Complete retained horizon: 4,096 genesis leaves plus two per 50,000 effects.
pub const MAX_OUTPUTS: usize = 104_096;

/// Returned only after the entire selected public stream and every sink call
/// succeeds. Not peer authority, a balance, or a retained-history checkpoint.
#[must_use]
pub struct CompleteScan {
    scanned: u64,
    matched: u64,
}
impl CompleteScan {
    /// Public occurrences examined, including ordinary decryption misses.
    #[must_use]
    pub const fn scanned(&self) -> u64 {
        self.scanned
    }
    /// Successfully delivered private observations.
    #[must_use]
    pub const fn matched(&self) -> u64 {
        self.matched
    }
}

fn check_range(state: &BranchState) -> Result<()> {
    if state.recovery_len() > MAX_OUTPUTS
        || state.recovery_len() as u64 != state.leaves()
        || state.genesis_leaves() > state.leaves()
        || state.eligible_cut().leaves > state.leaves()
    {
        return Err(Error::Unavailable("complete scanner horizon"));
    }
    Ok(())
}

/// Derived local note state. Maturity does not imply finality or absence of rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteStatus {
    /// Canonically consumed at this snapshot.
    Spent,
    /// Accepted output not yet included in a completed cut.
    PendingCut,
    /// Included in a cut, but no eligible cut yet contains this occurrence.
    IncludedImmature,
    /// Positive positioned note is unspent and included in the chosen eligible cut.
    SpendableAtCut,
    /// Valid zero note retained for recovery, not counted as positive funding.
    ZeroValue,
}
/// Wallet-private recovered note; not a public node response or network query.
pub struct RecoveredNote {
    /// Standard ZIP-212 note.
    pub note: Note,
    /// Authenticated decrypted diversified address.
    pub address: PaymentAddress,
    /// Canonical leaf position, not output slot or archive ordinal.
    pub position: u64,
    /// Position-bound nullifier under this viewing key.
    pub nullifier: Digest,
    /// Local canonical state derived from the full snapshot.
    pub status: NoteStatus,
    /// Exact authenticated memo, which is not necessarily zero for peer outputs.
    pub memo: [u8; 512],
}

/// Receive-only cut membership. None of these variants claim unspentness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingCutStatus {
    /// No completed cut includes this occurrence yet.
    PendingCut,
    /// A completed cut includes it, but no currently eligible cut does.
    IncludedImmature,
    /// Included in the currently eligible cut; MAY ALREADY BE SPENT.
    IncludedEligible,
}
/// Receive-only local observation, without nullifier or spendability assertions.
pub struct IncomingNote {
    /// Decrypted private note.
    pub note: Note,
    /// Authenticated recipient address.
    pub address: PaymentAddress,
    /// Complete canonical occurrence position.
    pub position: u64,
    /// Cut membership only, not spendability or finality.
    pub cut_status: IncomingCutStatus,
    /// Preserve memo bytes; zero is a wallet convention, not an admission rule.
    pub memo: [u8; 512],
}
/// Outgoing private observation from a canonically accepted ordinary effect.
/// Includes change/self-payments; do not add these values to incoming balance.
pub struct OutgoingNote {
    /// Accepted economic effect, not a representation-delivery receipt.
    pub effect: Digest,
    /// Canonical output occurrence.
    pub position: u64,
    /// Decrypted outgoing note, not its recipient's spending authority.
    pub note: Note,
    /// Authenticated destination.
    pub address: PaymentAddress,
    /// Authenticated memo, retained exactly.
    pub memo: [u8; 512],
}

/// Receive-only full-range walk. Never reports a note as unspent/spendable.
/// Missing complete history must be rejected by the local snapshot adapter.
pub fn scan_incoming(
    state: &BranchState,
    ivk: &PreparedIncomingViewingKey,
) -> Result<Vec<IncomingNote>> {
    let mut found = Vec::new();
    let _complete = visit_incoming(state, ivk, |note| {
        found.push(note);
        Ok(())
    })?;
    Ok(found)
}

/// Receive-only complete-range walk retaining only one decoded observation at a
/// time. The sink owns its buffering/storage limits. Stage sink changes and only
/// publish them after `Ok(CompleteScan)`; any failure leaves an incomplete walk.
/// This is an in-process API, not a scanner process/memory isolation boundary.
pub fn visit_incoming(
    state: &BranchState,
    ivk: &PreparedIncomingViewingKey,
    mut sink: impl FnMut(IncomingNote) -> Result<()>,
) -> Result<CompleteScan> {
    check_range(state)?;
    let mut matched = 0;
    for (position, entry) in state.recovery_iter().enumerate() {
        let output = RecoveryOutput::decode(**entry)?;
        if let Some((note, address, memo)) = output.decrypt_ivk(ivk) {
            let position = position as u64;
            let cut_status = if position < state.eligible_cut().leaves {
                IncomingCutStatus::IncludedEligible
            } else if state.cuts().last().is_some_and(|cut| position < cut.leaves) {
                IncomingCutStatus::IncludedImmature
            } else {
                IncomingCutStatus::PendingCut
            };
            sink(IncomingNote {
                note,
                address,
                position,
                cut_status,
                memo,
            })?;
            matched += 1;
        }
    }
    Ok(CompleteScan {
        scanned: state.leaves(),
        matched,
    })
}

/// Outgoing full accepted-order walk using exact locally derived cv linkage.
/// Genesis allocations lack retained cv and are explicitly outside this stream.
/// No peer lookup is made for a selected note, address, effect or nullifier.
pub fn scan_outgoing(state: &BranchState, ovk: &OutgoingViewingKey) -> Result<Vec<OutgoingNote>> {
    let mut found = Vec::new();
    let _complete = visit_outgoing(state, ovk, |note| {
        found.push(note);
        Ok(())
    })?;
    Ok(found)
}

/// Complete ordinary-output walk without accumulating private notes/memos.
/// Genesis is excluded because it has no retained outgoing commitment linkage.
/// Sink effects are provisional until success, as with `visit_incoming`.
pub fn visit_outgoing(
    state: &BranchState,
    ovk: &OutgoingViewingKey,
    mut sink: impl FnMut(OutgoingNote) -> Result<()>,
) -> Result<CompleteScan> {
    check_range(state)?;
    let mut position = state.genesis_leaves();
    let mut matched = 0;
    for row in state.accepted_outputs_iter() {
        if row.first_position != position || !state.contains_effect(&row.effect) {
            return Err(Error::Unavailable("complete outgoing linkage order"));
        }
        for commitment in &row.commitments {
            let index = usize::try_from(position)
                .map_err(|_| Error::Unavailable("outgoing position overflow"))?;
            let entry = state
                .recovery_entry(index)
                .ok_or(Error::Unavailable("incomplete outgoing recovery range"))?;
            let output = RecoveryOutput::decode(**entry)?;
            if let Some((note, address, memo)) = output.recover_outgoing(ovk, commitment)? {
                sink(OutgoingNote {
                    effect: row.effect,
                    position,
                    note,
                    address,
                    memo,
                })?;
                matched += 1;
            }
            position = position
                .checked_add(1)
                .ok_or(Error::Unavailable("outgoing range overflow"))?;
        }
    }
    if position != state.leaves() {
        return Err(Error::Unavailable("incomplete outgoing linkage"));
    }
    Ok(CompleteScan {
        scanned: position - state.genesis_leaves(),
        matched,
    })
}
/// Scan all canonical public recovery entries in order, using constant-size input
/// buffers but retaining ALL matched notes/memos. Use `visit` to bound output
/// memory. A partial/unavailable snapshot is never an empty wallet.
pub fn scan(state: &BranchState, fvk: &FullViewingKey) -> Result<Vec<RecoveredNote>> {
    let mut found = Vec::new();
    let _complete = visit(state, fvk, |note| {
        found.push(note);
        Ok(())
    })?;
    Ok(found)
}

/// Full-view complete-range walk with one decoded observation at a time. Prepare
/// the incoming key once per walk. See `visit_incoming` for sink transaction and
/// process-isolation requirements; successful callbacks alone are NOT completion.
pub fn visit(
    state: &BranchState,
    fvk: &FullViewingKey,
    mut sink: impl FnMut(RecoveredNote) -> Result<()>,
) -> Result<CompleteScan> {
    check_range(state)?;
    let ivk = PreparedIncomingViewingKey::new(&fvk.vk.ivk());
    let mut matched = 0;
    let cut = state.eligible_cut();
    for (position, entry) in state.recovery_iter().enumerate() {
        let output = RecoveryOutput::decode(**entry)?;
        if let Some((note, address, memo)) = output.decrypt_ivk(&ivk) {
            let position = position as u64;
            let nf = note.nf(&fvk.vk.nk, position).0;
            let status = if state.contains_nullifier(&nf) {
                NoteStatus::Spent
            } else if note.value().inner() == 0 {
                NoteStatus::ZeroValue
            } else if position < cut.leaves {
                NoteStatus::SpendableAtCut
            } else if state.cuts().last().is_some_and(|c| position < c.leaves) {
                NoteStatus::IncludedImmature
            } else {
                NoteStatus::PendingCut
            };
            sink(RecoveredNote {
                note,
                address,
                position,
                nullifier: nf,
                status,
                memo,
            })?;
            matched += 1;
        }
    }
    Ok(CompleteScan {
        scanned: state.leaves(),
        matched,
    })
}

/// Reconstruct one witness by a full public range walk. No note-specific peer fetch.
/// At most two selected inputs need this bounded-memory pass for one envelope.
pub fn witness_at_cut(state: &BranchState, cut: &Cut, position: u64) -> Result<MerklePath> {
    if cut.index > state.eligible_cut().index
        || state.cuts().get(cut.index as usize) != Some(cut)
        || position >= cut.leaves
    {
        return Err(Error::Unavailable("no eligible canonical witness cut"));
    }
    let mut tree = CommitmentTree::empty();
    let mut witness: Option<IncrementalWitness> = None;
    let leaves =
        usize::try_from(cut.leaves).map_err(|_| Error::Unavailable("witness range overflow"))?;
    for (i, entry) in state.recovery_iter().take(leaves).enumerate() {
        let node = Option::<Node>::from(Node::from_bytes(
            entry[..32].try_into().expect("fixed recovery"),
        ))
        .ok_or(Error::Unavailable("authenticated commitment encoding"))?;
        tree.append(node)
            .map_err(|()| Error::Unavailable("witness tree capacity"))?;
        if let Some(w) = witness.as_mut() {
            w.append(node)
                .map_err(|()| Error::Unavailable("witness capacity"))?;
        }
        if i as u64 == position {
            witness = IncrementalWitness::from_tree(tree.clone());
        }
    }
    if tree.size() as u64 != cut.leaves || tree.root().to_bytes() != cut.root {
        return Err(Error::Unavailable(
            "incomplete or mismatched recovery range",
        ));
    }
    witness
        .and_then(|w| w.path())
        .ok_or(Error::Unavailable("witness missing"))
}
