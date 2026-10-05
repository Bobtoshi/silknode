//! Local physical sharing only. Every read reconstructs the exact SNF04OR1
//! bytes and verifies their original hash; no page conveys ordering validity.
use super::{MAX_OBJECT, ObjectReader, Store, charge};
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    wire::{raw_hash, u32le},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs::File, io::Write};

const HEADER: usize = 76;
const ROWS: usize = 64;
const FANOUT: usize = 8;
const LIMIT: usize = ROWS * FANOUT * FANOUT;
const _: () = assert!(LIMIT == crate::sync::HISTORY_LIMIT_V1);
const DESCRIPTOR: usize = 8 + HEADER + 32;
const PAGE_LIMIT: usize = 12 + ROWS * 32;
const DAMAGED: &str = "retained order representation damaged";

fn count(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < HEADER || bytes.get(..8) != Some(b"SNF04OR1") {
        return Err(Error::Unavailable(DAMAGED));
    }
    let count = usize::try_from(u32le(bytes, 72)?).map_err(|_| Error::Unavailable(DAMAGED))?;
    if count > LIMIT || bytes.len() != HEADER + count * 32 {
        return Err(Error::Unavailable(DAMAGED));
    }
    Ok(count)
}

struct Page {
    id: Digest,
    bytes: Vec<u8>,
}
#[cfg(test)]
struct Tree {
    descriptor: Vec<u8>,
    pages: Vec<Page>,
}
fn page_header(
    magic: [u8; 8],
    level_or_rows: usize,
    children: usize,
    base: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::from(magic.as_slice());
    bytes.push(u8::try_from(level_or_rows).map_err(|_| Error::Unavailable(DAMAGED))?);
    bytes.push(u8::try_from(children).map_err(|_| Error::Unavailable(DAMAGED))?);
    bytes.extend_from_slice(
        &u16::try_from(base)
            .map_err(|_| Error::Unavailable(DAMAGED))?
            .to_le_bytes(),
    );
    Ok(bytes)
}
#[cfg(test)]
impl Tree {
    fn derive(order: &[u8], budget: &JobBudget) -> Result<Self> {
        let n = count(order)?;
        if n <= ROWS {
            return Err(Error::Unavailable(
                "shared order requires more than one leaf",
            ));
        }
        let mut pages = Vec::new();
        let mut leaves = Vec::new();
        for (base, rows) in order[HEADER..].chunks(ROWS * 32).enumerate() {
            budget.check()?;
            let mut bytes = page_header(*b"SNF04OL1", rows.len() / 32, 0, base)?;
            bytes.extend_from_slice(rows);
            let id = raw_hash(&bytes);
            pages.push(Page { id, bytes });
            leaves.push(id);
        }
        let mut branches = Vec::new();
        for (i, children) in leaves.chunks(FANOUT).enumerate() {
            budget.check()?;
            let mut bytes = page_header(*b"SNF04OB1", 1, children.len(), i * FANOUT)?;
            for id in children {
                bytes.extend_from_slice(id);
            }
            let id = raw_hash(&bytes);
            pages.push(Page { id, bytes });
            branches.push(id);
        }
        budget.check()?;
        let mut bytes = page_header(*b"SNF04OB1", 2, branches.len(), 0)?;
        for id in branches {
            bytes.extend_from_slice(&id);
        }
        let root = raw_hash(&bytes);
        pages.push(Page { id: root, bytes });
        let mut descriptor = Vec::from(b"SNF04OT1".as_slice());
        descriptor.extend_from_slice(&order[..HEADER]);
        descriptor.extend_from_slice(&root);
        Ok(Self { descriptor, pages })
    }
}

/// Derive identical existing tree bytes in a depth-first page walk. Production
/// planning retains addresses/lengths only, never every physical page payload.
fn visit_tree(
    order: &[u8],
    budget: &JobBudget,
    visit: &mut impl FnMut(Page) -> Result<()>,
) -> Result<Vec<u8>> {
    let n = count(order)?;
    if n <= ROWS {
        return Err(Error::Unavailable(
            "shared order requires more than one leaf",
        ));
    }
    let mut roots = Vec::with_capacity(FANOUT);
    for (group, rows) in order[HEADER..].chunks(ROWS * FANOUT * 32).enumerate() {
        let mut children = Vec::with_capacity(FANOUT);
        for (offset, rows) in rows.chunks(ROWS * 32).enumerate() {
            budget.check()?;
            let mut bytes = page_header(*b"SNF04OL1", rows.len() / 32, 0, group * FANOUT + offset)?;
            bytes.extend_from_slice(rows);
            let id = raw_hash(&bytes);
            visit(Page { id, bytes })?;
            children.push(id);
        }
        budget.check()?;
        let mut bytes = page_header(*b"SNF04OB1", 1, children.len(), group * FANOUT)?;
        for id in children {
            bytes.extend_from_slice(&id);
        }
        let id = raw_hash(&bytes);
        visit(Page { id, bytes })?;
        roots.push(id);
    }
    budget.check()?;
    let mut bytes = page_header(*b"SNF04OB1", 2, roots.len(), 0)?;
    for id in roots {
        bytes.extend_from_slice(&id);
    }
    let root = raw_hash(&bytes);
    visit(Page { id: root, bytes })?;
    budget.check()?;
    let mut descriptor = Vec::from(b"SNF04OT1".as_slice());
    descriptor.extend_from_slice(&order[..HEADER]);
    descriptor.extend_from_slice(&root);
    Ok(descriptor)
}

impl ObjectReader {
    /// Typed canonical-order read. A damaged legacy raw object is never hidden
    /// by a virtual representation, and nested damage never permits HEAD repair.
    pub(crate) fn order(&self, id: Digest, limit: usize, budget: &JobBudget) -> Result<Vec<u8>> {
        let mut bytes = vec![0; HEADER];
        let header = self.visit_order(id, limit, budget, &mut |rows| {
            bytes.extend_from_slice(rows);
            Ok(())
        })?;
        bytes[..HEADER].copy_from_slice(&header);
        Ok(bytes)
    }
    /// Private staging visitor only. Shared orders retain at most one leaf and
    /// two branch pages, not the complete canonical payload. Visitor observations
    /// MUST remain provisional until the entire canonical hash has passed.
    pub(crate) fn visit_order(
        &self,
        id: Digest,
        limit: usize,
        budget: &JobBudget,
        visit: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<[u8; HEADER]> {
        budget.check()?;
        if limit > HEADER + LIMIT * 32 {
            return Err(Error::Unavailable(DAMAGED));
        }
        budget.source()?;
        match self.object(id, limit) {
            Ok(bytes) => {
                count(&bytes)?;
                for rows in bytes[HEADER..].chunks(ROWS * 32) {
                    budget.check()?;
                    visit(rows)?;
                }
                budget.check()?;
                return bytes[..HEADER]
                    .try_into()
                    .map_err(|_| Error::Unavailable(DAMAGED));
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Unavailable(DAMAGED)),
        }
        budget.source()?;
        let descriptor = match self.named(&format!("{}.ord", hex::encode(id)), DESCRIPTOR) {
            Ok(bytes) => bytes,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Io(e));
            }
            Err(_) => return Err(Error::Unavailable(DAMAGED)),
        };
        if descriptor.len() != DESCRIPTOR
            || descriptor.get(..8) != Some(b"SNF04OT1")
            || descriptor.get(8..16) != Some(b"SNF04OR1")
        {
            return Err(Error::Unavailable(DAMAGED));
        }
        let n = usize::try_from(u32le(&descriptor, 8 + 72)?)
            .map_err(|_| Error::Unavailable(DAMAGED))?;
        if !(ROWS + 1..=LIMIT).contains(&n) || HEADER + n * 32 > limit {
            return Err(Error::Unavailable(DAMAGED));
        }
        let root: Digest = descriptor[8 + HEADER..]
            .try_into()
            .map_err(|_| Error::Unavailable(DAMAGED))?;
        let header: [u8; HEADER] = descriptor[8..8 + HEADER]
            .try_into()
            .map_err(|_| Error::Unavailable(DAMAGED))?;
        let mut hash = Sha256::new();
        hash.update(header);
        self.order_branch(
            root,
            2,
            0,
            n,
            &mut |rows| {
                hash.update(rows);
                visit(rows)
            },
            budget,
        )?;
        let canonical: Digest = hash.finalize().into();
        if canonical != id {
            return Err(Error::Unavailable(DAMAGED));
        }
        budget.check()?;
        Ok(header)
    }
    fn order_page(&self, id: Digest, budget: &JobBudget) -> Result<Vec<u8>> {
        budget.check()?;
        budget.source()?;
        self.object(id, PAGE_LIMIT)
            .map_err(|_| Error::Unavailable(DAMAGED))
    }
    fn order_branch(
        &self,
        id: Digest,
        level: usize,
        base: usize,
        n: usize,
        visit: &mut impl FnMut(&[u8]) -> Result<()>,
        budget: &JobBudget,
    ) -> Result<()> {
        let bytes = self.order_page(id, budget)?;
        let stride = if level == 2 { FANOUT } else { 1 };
        let remaining_pages = n.div_ceil(ROWS) - base;
        let children = remaining_pages.div_ceil(stride).min(FANOUT);
        let header = page_header(*b"SNF04OB1", level, children, base)?;
        if bytes.len() != 12 + children * 32 || bytes.get(..12) != Some(header.as_slice()) {
            return Err(Error::Unavailable(DAMAGED));
        }
        for (i, row) in bytes[12..].chunks_exact(32).enumerate() {
            let child = row.try_into().map_err(|_| Error::Unavailable(DAMAGED))?;
            let child_base = base + i * stride;
            if level == 2 {
                self.order_branch(child, 1, child_base, n, visit, budget)?;
            } else {
                let leaf = self.order_page(child, budget)?;
                let rows = (n - child_base * ROWS).min(ROWS);
                let header = page_header(*b"SNF04OL1", rows, 0, child_base)?;
                if leaf.len() != 12 + rows * 32 || leaf.get(..12) != Some(header.as_slice()) {
                    return Err(Error::Unavailable(DAMAGED));
                }
                visit(&leaf[12..])?;
            }
        }
        Ok(())
    }
}

enum Plan {
    Existing,
    Raw,
    Shared {
        descriptor: Vec<u8>,
        missing: BTreeMap<Digest, usize>,
    },
}
impl Store {
    pub(crate) fn order_object(&self, id: Digest, budget: &JobBudget) -> Result<Vec<u8>> {
        self.object_reader()?.order(id, HEADER + LIMIT * 32, budget)
    }
    fn plan_order(&self, order: &[u8], budget: &JobBudget) -> Result<Plan> {
        let n = count(order)?;
        let reader = self.object_reader()?;
        let mut at = HEADER;
        let existing = reader.visit_order(raw_hash(order), order.len(), budget, &mut |rows| {
            let end = at
                .checked_add(rows.len())
                .ok_or(Error::Unavailable(DAMAGED))?;
            if order.get(at..end) != Some(rows) {
                return Err(Error::Unavailable(DAMAGED));
            }
            at = end;
            Ok(())
        });
        match existing {
            Ok(header) if order[..HEADER] == header && at == order.len() => {
                return Ok(Plan::Existing);
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(error @ Error::Paused(_)) => return Err(error),
            _ => return Err(Error::Unavailable(DAMAGED)),
        }
        if n <= ROWS {
            return Ok(Plan::Raw);
        }
        if self.active_job()?.is_none() && self.active_replay()?.is_none() {
            return Err(Error::Unavailable(
                "shared order requires active verified transition",
            ));
        }
        let mut missing = BTreeMap::new();
        let descriptor = visit_tree(order, budget, &mut |page| {
            budget.check()?;
            budget.source()?;
            match reader.object(page.id, PAGE_LIMIT) {
                Ok(bytes) if bytes == page.bytes => {}
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    if missing.insert(page.id, page.bytes.len()).is_some() {
                        return Err(Error::Unavailable("duplicate derived order page"));
                    }
                }
                _ => return Err(Error::Unavailable(DAMAGED)),
            }
            Ok(())
        })?;
        Ok(Plan::Shared {
            descriptor,
            missing,
        })
    }
    /// Preserve generation/commitment bytes while sharing only physical order
    /// storage. The original caller budget spans planning, reads and writes.
    pub(crate) fn commit_ordered(
        &mut self,
        objects: &[&[u8]],
        order: &[u8],
        head: &[u8],
        budget: &JobBudget,
    ) -> Result<Digest> {
        let plan = match self.plan_order(order, budget) {
            Ok(plan) => plan,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let mut total = 4 * 4096_u64;
        for bytes in objects.iter().chain(std::iter::once(&head)) {
            if bytes.len() > MAX_OBJECT {
                return Err(Error::Paused("snapshot object chunk"));
            }
            total = total
                .checked_add(charge(
                    u64::try_from(bytes.len())
                        .map_err(|_| Error::Paused("commit group overflow"))?,
                ))
                .ok_or(Error::Paused("commit group overflow"))?;
        }
        let order_charge = match &plan {
            Plan::Existing => 0,
            Plan::Raw => charge(
                u64::try_from(order.len()).map_err(|_| Error::Paused("commit group overflow"))?,
            ),
            Plan::Shared {
                descriptor,
                missing,
            } => missing.values().try_fold(
                charge(
                    u64::try_from(descriptor.len())
                        .map_err(|_| Error::Paused("commit group overflow"))?,
                ),
                |sum, size| {
                    sum.checked_add(charge(
                        u64::try_from(*size).map_err(|_| Error::Paused("commit group overflow"))?,
                    ))
                    .ok_or(Error::Paused("commit group overflow"))
                },
            )?,
        };
        total = total
            .checked_add(order_charge)
            .ok_or(Error::Paused("commit group overflow"))?;
        budget.check()?;
        self.reserve(total)?;
        self.used += total;
        self.poisoned = true;
        let written = (|| {
            for bytes in objects {
                budget.check()?;
                budget.source()?;
                self.put(bytes)?;
            }
            match plan {
                Plan::Existing => {}
                Plan::Raw => {
                    budget.check()?;
                    budget.source()?;
                    self.put(order)?;
                }
                Plan::Shared {
                    descriptor,
                    mut missing,
                } => {
                    let regenerated = visit_tree(order, budget, &mut |page| {
                        budget.check()?;
                        if let Some(size) = missing.remove(&page.id) {
                            if size != page.bytes.len() {
                                return Err(Error::Unavailable("derived order plan mismatch"));
                            }
                            budget.source()?;
                            self.put(&page.bytes)?;
                        }
                        Ok(())
                    })?;
                    if !missing.is_empty() || regenerated != descriptor {
                        return Err(Error::Unavailable("derived order plan mismatch"));
                    }
                    self.directory.sync_all()?;
                    budget.check()?;
                    budget.source()?;
                    self.put_order_descriptor(raw_hash(order), &descriptor)?;
                }
            }
            budget.check()?;
            budget.source()?;
            let id = self.put(head)?;
            budget.check()?;
            self.publish_written_head(id)
        })();
        // Uncertain new writes cannot be misclassified as old HEAD damage.
        match written {
            Err(
                Error::Io(_)
                | Error::Unavailable(
                    "content object hash" | "store object type/length" | "changed store object",
                ),
            ) => Err(Error::Unavailable("order commit publication failed")),
            other => other,
        }
    }
    fn put_order_descriptor(&self, id: Digest, bytes: &[u8]) -> Result<()> {
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable("order temporary entropy"))?;
        let stage = format!("order-stage-{}", hex::encode(nonce));
        let mut file: File = rustix::fs::openat(
            &self.directory,
            stage.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?
        .into();
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            &self.directory,
            stage.as_str(),
            &self.directory,
            format!("{}.ord", hex::encode(id)).as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
