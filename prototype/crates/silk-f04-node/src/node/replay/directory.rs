//! Rebuilt, bounded-fanout address directory. No saved verification authority.
use crate::{
    Digest, Error, Result,
    capacity::MAX_GENERATIONS_V1,
    store::Store,
    wire::{field, u64le},
};

const FANOUT: usize = 64;
const HEADER: usize = 56;
const LEVELS: usize = 3;
const _: () = assert!(MAX_GENERATIONS_V1 <= 64 * 64 * 64 * 64);

struct Page {
    domain: Digest,
    // Base CHILD ordinal at this level, aligned to FANOUT. Level zero's
    // children are original SNF04RP2 leaves, not generation records.
    base: u64,
    level: u8,
    children: Vec<Digest>,
}
impl Page {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + self.children.len() * 32);
        bytes.extend_from_slice(b"SNF04RD1");
        bytes.extend_from_slice(&self.domain);
        bytes.extend_from_slice(&self.base.to_le_bytes());
        bytes.push(self.level);
        bytes.push(u8::try_from(self.children.len()).expect("bounded directory fanout"));
        bytes.extend_from_slice(&[0; 6]);
        for child in &self.children {
            bytes.extend_from_slice(child);
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if !(HEADER + 32..=HEADER + FANOUT * 32).contains(&bytes.len())
            || &bytes[..8] != b"SNF04RD1"
            || bytes[50..56] != [0; 6]
        {
            return Err(Error::Unavailable("retained replay directory encoding"));
        }
        let count = usize::from(bytes[49]);
        let level = bytes[48];
        let base = u64le(bytes, 40)?;
        if !(1..=FANOUT).contains(&count)
            || bytes.len() != HEADER + count * 32
            || usize::from(level) >= LEVELS
            || !base.is_multiple_of(FANOUT as u64)
        {
            return Err(Error::Unavailable("retained replay directory shape"));
        }
        let children = bytes[HEADER..]
            .chunks_exact(32)
            .map(|child| child.try_into().expect("fixed directory address"))
            .collect::<Vec<_>>();
        if children.contains(&[0; 32]) {
            return Err(Error::Unavailable(
                "missing retained replay directory child",
            ));
        }
        Ok(Self {
            domain: field(bytes, 8)?,
            base,
            level,
            children,
        })
    }
}

/// Only a fresh build creates this handle. It is not decoded from a saved root.
pub(super) struct Directory {
    domain: Digest,
    pub(super) root: Digest,
    level: u8,
    leaves: u64,
}
impl Directory {
    /// Read at most one directory payload at a time. Every path checks exact
    /// context, height, aligned ordinal and tail count; read/hash damage is a
    /// STOP, never permission to fall back to an older canonical HEAD.
    pub(super) fn leaf(&self, store: &Store, ordinal: u64) -> Result<Digest> {
        if ordinal >= self.leaves {
            return Err(Error::Unavailable("retained replay directory ordinal"));
        }
        let mut id = self.root;
        let mut base = 0;
        for level in (0..=self.level).rev() {
            let bytes = store
                .object(id)
                .map_err(|_| Error::Unavailable("retained replay directory load failed"))?;
            let page = Page::decode(&bytes)?;
            let scale = (FANOUT as u64).pow(u32::from(level));
            let total_children = self.leaves.div_ceil(scale);
            let count = total_children
                .checked_sub(base)
                .ok_or(Error::Unavailable("retained replay directory coverage"))?
                .min(FANOUT as u64);
            if page.domain != self.domain
                || page.level != level
                || page.base != base
                || page.children.len() as u64 != count
            {
                return Err(Error::Unavailable(
                    "retained replay directory binding/coverage",
                ));
            }
            let child = ordinal / scale;
            let index = usize::try_from(
                child
                    .checked_sub(base)
                    .ok_or(Error::Unavailable("retained replay directory coverage"))?,
            )
            .map_err(|_| Error::Unavailable("retained replay directory index"))?;
            id = *page
                .children
                .get(index)
                .ok_or(Error::Unavailable("retained replay directory coverage"))?;
            base = child
                .checked_mul(FANOUT as u64)
                .ok_or(Error::Unavailable("retained replay directory arithmetic"))?;
        }
        Ok(id)
    }
}

struct Pending {
    base: u64,
    end: u64,
    children: Vec<Digest>,
}

/// Descending construction matches the original backward lineage walk. At most
/// three pending 64-address groups exist, independent of generation count.
pub(super) struct Builder {
    domain: Digest,
    leaves: u64,
    remaining: u64,
    level: u8,
    pending: [Option<Pending>; LEVELS],
    root: Option<Digest>,
}
impl Builder {
    pub(super) fn new(domain: Digest, total: u64) -> Result<Self> {
        if total == 0 || total > MAX_GENERATIONS_V1 {
            return Err(Error::Unavailable("retained replay directory envelope"));
        }
        let leaves = total.div_ceil(FANOUT as u64);
        let mut level = 0_u8;
        let mut capacity = FANOUT as u64;
        while leaves > capacity {
            level += 1;
            capacity *= FANOUT as u64;
        }
        if usize::from(level) >= LEVELS {
            return Err(Error::Unavailable("retained replay directory height"));
        }
        Ok(Self {
            domain,
            leaves,
            remaining: leaves,
            level,
            pending: std::array::from_fn(|_| None),
            root: None,
        })
    }
    pub(super) fn push(&mut self, store: &mut Store, ordinal: u64, id: Digest) -> Result<()> {
        if self.remaining == 0 || ordinal != self.remaining - 1 || id == [0; 32] {
            return Err(Error::Unavailable("retained replay directory source order"));
        }
        self.push_level(store, 0, ordinal, id)?;
        self.remaining -= 1;
        Ok(())
    }
    fn push_level(&mut self, store: &mut Store, level: u8, ordinal: u64, id: Digest) -> Result<()> {
        let base = ordinal / FANOUT as u64 * FANOUT as u64;
        let pending = self.pending[usize::from(level)].get_or_insert_with(|| Pending {
            base,
            end: ordinal + 1,
            children: Vec::with_capacity(FANOUT),
        });
        if pending.base != base
            || pending.end != ordinal + pending.children.len() as u64 + 1
            || pending.children.len() >= FANOUT
        {
            return Err(Error::Unavailable("retained replay directory construction"));
        }
        pending.children.push(id);
        if ordinal != base {
            return Ok(());
        }
        let mut pending = self.pending[usize::from(level)]
            .take()
            .expect("completed bounded group");
        pending.children.reverse();
        let bytes = Page {
            domain: self.domain,
            base,
            level,
            children: pending.children,
        }
        .encode();
        let parent = store.retain_replay_page(&bytes)?;
        if level == self.level {
            if base != 0 || self.root.replace(parent).is_some() {
                return Err(Error::Unavailable("retained replay directory root"));
            }
        } else {
            self.push_level(store, level + 1, base / FANOUT as u64, parent)?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<Directory> {
        if self.remaining != 0 || self.pending.iter().any(Option::is_some) {
            return Err(Error::Unavailable("incomplete retained replay directory"));
        }
        Ok(Directory {
            domain: self.domain,
            leaves: self.leaves,
            level: self.level,
            root: self
                .root
                .ok_or(Error::Unavailable("missing retained replay directory root"))?,
        })
    }
}

#[cfg(test)]
mod tests;
