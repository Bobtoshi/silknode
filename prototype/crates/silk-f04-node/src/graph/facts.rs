//! Compact live parent-fact binding, never persisted or imported as validity.
use crate::{
    Digest, Error, Result,
    carriage::{Header, ParentFacts},
    wire::raw_hash,
};

#[derive(Clone)]
pub(super) enum FactsRecord {
    Resident(Box<ParentFacts>),
    Retained {
        minimum_time: u64,
        key_material: Digest,
        binding: Digest,
    },
}
fn binding(facts: &ParentFacts) -> Digest {
    // Operation-local bytes only. This does not alter any retained record.
    let mut bytes = Vec::with_capacity(376);
    bytes.extend_from_slice(&facts.source_record);
    bytes.extend_from_slice(&facts.epoch.to_le_bytes());
    bytes.extend_from_slice(&facts.daa);
    bytes.extend_from_slice(&facts.work.to_le_bytes());
    bytes.extend_from_slice(&facts.minimum_time.to_le_bytes());
    bytes.extend_from_slice(&facts.source_index.to_le_bytes());
    bytes.extend_from_slice(&facts.source_checkpoint);
    bytes.extend_from_slice(&facts.source_j);
    bytes.extend_from_slice(&facts.seed);
    bytes.extend_from_slice(&facts.key_material);
    raw_hash(&bytes)
}
impl FactsRecord {
    pub(super) fn retain(&self) -> Self {
        match self {
            Self::Resident(facts) => Self::Retained {
                minimum_time: facts.minimum_time,
                key_material: facts.key_material,
                binding: binding(facts),
            },
            Self::Retained { .. } => self.clone(),
        }
    }
    /// Call ONLY after exact original full-record and header binding checks.
    pub(super) fn restore(&self, header: &Header, source_record: [u8; 184]) -> Result<Self> {
        let facts = match self {
            Self::Resident(facts) => {
                if facts.source_record != source_record {
                    return Err(Error::Unavailable("resident parent source mismatch"));
                }
                header.check_facts(facts)?;
                return Ok(Self::Resident(facts.clone()));
            }
            Self::Retained {
                minimum_time,
                key_material,
                binding: expected,
            } => {
                let facts = ParentFacts {
                    source_record,
                    epoch: header.epoch,
                    daa: header.daa,
                    work: header.work,
                    minimum_time: *minimum_time,
                    source_index: header.source_index,
                    source_checkpoint: header.source_checkpoint,
                    source_j: header.source_j,
                    seed: header.seed,
                    key_material: *key_material,
                };
                if binding(&facts) != *expected {
                    return Err(Error::Unavailable("retained parent facts binding mismatch"));
                }
                facts
            }
        };
        header.check_facts(&facts)?;
        Ok(Self::Resident(Box::new(facts)))
    }
    pub(super) const fn resident(&self) -> &ParentFacts {
        match self {
            Self::Resident(facts) => facts,
            // Only resident or exactly restored carriers implement public borrows.
            Self::Retained { .. } => panic!("verified execution carrier must own parent facts"),
        }
    }
}
