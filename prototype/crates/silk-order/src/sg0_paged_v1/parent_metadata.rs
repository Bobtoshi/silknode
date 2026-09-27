//! Candidate metadata from a replay-checked parent closure, not a full graph
//! snapshot. Only this ordering module constructs the resulting metadata.
use super::*;

/// Opaque, receiver-derived candidate template. Own work is joined only after
/// the node has verified the exact candidate's proof of work. This object is
/// not serializable and carries no work, admission or settlement authority.
#[derive(Clone)]
pub struct VerifiedPagedVertexTemplateV1 {
    parents: Sg0ParentSetV1,
    selected: Sg0SelectedParentV1,
    selected_score: u128,
    selected_work: Uint256,
    blues: Vec<VertexId>,
    red: u64,
    merge_hash: Hash32,
    merge_work: Uint256,
}
impl VerifiedPagedVertexTemplateV1 {
    /// Exact receiver-checked parent shape.
    pub fn parent_set(&self) -> &Sg0ParentSetV1 {
        &self.parents
    }
    /// Apply checked arithmetic to already receiver-verified candidate work.
    /// The caller must still verify the prospective virtual order and fence.
    pub fn with_verified_work(&self, own: Uint256) -> Result<Sg0VertexDataV1> {
        if own.is_zero() {
            return Err(Sg0Error::ZeroWork);
        }
        Ok(Sg0VertexDataV1 {
            selected_parent: self.selected,
            merge_blues: self.blues.clone(),
            merge_red_count: self.red,
            merge_order_commitment: self.merge_hash,
            blue_score: self
                .selected_score
                .checked_add(1)
                .and_then(|score| score.checked_add(self.blues.len() as u128))
                .ok_or(Sg0Error::ScoreOverflow)?,
            blue_work: self
                .selected_work
                .checked_add(own)
                .and_then(|work| work.checked_add(self.merge_work))
                .ok_or(Sg0Error::WorkOverflow)?,
        })
    }
}

/// Bounded two-pass merge hashing. Consensus length-prefixed hashes require a
/// counting pass; at most 64 order entries are read per advance. The existing
/// local 4096 merge-blue bound is retained, not made into a consensus rule.
#[derive(Clone)]
pub struct PagedParentMetadataV1 {
    parent: VerifiedPagedParentV1,
    cursor: u64,
    count: u64,
    collecting: bool,
    done: bool,
    hash: Sha256,
    template: VerifiedPagedVertexTemplateV1,
}
impl VerifiedPagedParentV1 {
    /// Begin candidate metadata derivation for this exact parent-local order.
    pub fn begin_vertex_template(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<PagedParentMetadataV1> {
        self.check(g, t)?;
        let selected = match self.selected {
            Sg0SelectedParentV1::Anchor => None,
            Sg0SelectedParentV1::Vertex(id) => Some(metadata(g, id)?),
        };
        Ok(PagedParentMetadataV1 {
            parent: self.clone(),
            cursor: 0,
            count: 0,
            collecting: false,
            done: false,
            hash: Sha256::new(),
            template: VerifiedPagedVertexTemplateV1 {
                parents: self.parents.clone(),
                selected: self.selected,
                selected_score: selected.as_ref().map_or(0, Sg0VertexDataV1::blue_score),
                selected_work: selected
                    .as_ref()
                    .map_or(Uint256::ZERO, Sg0VertexDataV1::blue_work),
                blues: Vec::new(),
                red: 0,
                merge_hash: Hash32::new([0; 32]),
                merge_work: Uint256::ZERO,
            },
        })
    }
}
impl PagedParentMetadataV1 {
    /// Errors preserve the continuation. No graph inventory or reference
    /// ordering routine is available through this path.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VerifiedPagedVertexTemplateV1>> {
        self.parent.check(g, t)?;
        if self.done {
            return Err(Sg0Error::Invariant);
        }
        let mut next = self.clone();
        for _ in 0..64 {
            if next.cursor == next.parent.order.total_count() {
                break;
            }
            let entry = next.parent.order.entry(g, t, next.cursor)?;
            next.cursor += 1;
            let below = match next.parent.selected {
                Sg0SelectedParentV1::Anchor => false,
                Sg0SelectedParentV1::Vertex(tip) => {
                    next.parent
                        .order
                        .is_ancestor_or_equal(g, t, entry.vertex_id, tip)?
                }
            };
            if below {
                continue;
            }
            if !next.collecting {
                next.count = next.count.checked_add(1).ok_or(Sg0Error::CountOverflow)?;
                continue;
            }
            let blue = entry.color == Sg0Color::Blue;
            next.hash.update(entry.vertex_id.as_bytes());
            next.hash.update([u8::from(blue)]);
            if blue {
                if next.template.blues.len() == 4096 {
                    return Err(Sg0Error::ResourceBudget);
                }
                next.template.blues.push(entry.vertex_id);
                next.template.merge_work = next
                    .template
                    .merge_work
                    .checked_add(work(g, entry.vertex_id)?)
                    .ok_or(Sg0Error::WorkOverflow)?;
            } else {
                next.template.red = next
                    .template
                    .red
                    .checked_add(1)
                    .ok_or(Sg0Error::CountOverflow)?;
            }
        }
        let output = if next.cursor != next.parent.order.total_count() {
            None
        } else if !next.collecting {
            next.cursor = 0;
            next.collecting = true;
            next.hash = start_hash(MERGE_COMMITMENT_DOMAIN, next.count);
            None
        } else {
            if next.template.blues.len() as u64 + next.template.red != next.count {
                return Err(Sg0Error::Invariant);
            }
            next.template.merge_hash = Hash32::new(next.hash.clone().finalize().into());
            next.done = true;
            Some(next.template.clone())
        };
        *self = next;
        Ok(output)
    }
}
