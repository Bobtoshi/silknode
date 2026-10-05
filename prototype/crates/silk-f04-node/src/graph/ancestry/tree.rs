//! Private extensible address tree, not admitted ancestry or a cold snapshot.
//! Path copying touches one eight-way branch per level; retained roots own no
//! complete leaf-address vector. Node coordinates come from the receiver walk.
use super::{Leaf, RetainedContext};
use crate::{Digest, Error, Result, budget::JobBudget, store::Store, wire::u64le};
use std::sync::Arc;

const FANOUT: usize = 8;
const HEADER: usize = 56;
const SIZE: usize = HEADER + FANOUT * 33;
const MAX_DEPTH: usize = (usize::BITS as usize - 1) / 3;

#[derive(Clone)]
enum Node {
    Leaf(Arc<Leaf>),
    Branch([Option<Arc<Node>>; FANOUT]),
    Retained(Digest),
}
#[derive(Clone, Default)]
pub(super) struct Pages {
    root: Option<Arc<Node>>,
    depth: usize,
}
fn span(depth: usize) -> Result<usize> {
    if depth > MAX_DEPTH {
        return Err(Error::Unavailable("ancestry directory depth"));
    }
    Ok(1_usize << (depth * 3))
}
fn check(budget: Option<&JobBudget>) -> Result<()> {
    budget.map_or(Ok(()), JobBudget::check)
}
fn branch(
    node: &Arc<Node>,
    depth: usize,
    base: usize,
    reader: Option<&Arc<RetainedContext>>,
    budget: Option<&JobBudget>,
) -> Result<[Option<Arc<Node>>; FANOUT]> {
    check(budget)?;
    match node.as_ref() {
        Node::Branch(children) if depth > 0 => Ok(children.clone()),
        Node::Retained(id) if depth > 0 => {
            let reader = reader.ok_or(Error::Unavailable("ancestry directory context"))?;
            if let Some(budget) = budget {
                budget.source()?;
            }
            let bytes = reader.objects().object(*id, SIZE)?;
            if bytes.len() != SIZE
                || &bytes[..8] != b"SNF04AD2"
                || bytes[8..40] != reader.domain()
                || u64le(&bytes, 40)? != base as u64
                || bytes[48] as usize != depth
                || bytes[49..HEADER].iter().any(|b| *b != 0)
            {
                return Err(Error::Unavailable("ancestry directory binding"));
            }
            let mut children = std::array::from_fn(|_| None);
            for (child, bytes) in children.iter_mut().zip(bytes[HEADER..].chunks_exact(33)) {
                match bytes[0] {
                    0 if bytes[1..].iter().all(|b| *b == 0) => {}
                    1 => {
                        *child =
                            Some(Arc::new(Node::Retained(bytes[1..].try_into().map_err(
                                |_| Error::Unavailable("ancestry directory address"),
                            )?)));
                    }
                    _ => return Err(Error::Unavailable("ancestry directory child")),
                }
            }
            if children.iter().all(Option::is_none) {
                return Err(Error::Unavailable("empty retained ancestry directory"));
            }
            check(budget)?;
            Ok(children)
        }
        _ => Err(Error::Unavailable("ancestry directory node kind")),
    }
}
impl Pages {
    pub(super) fn same_root(&self, other: &Self) -> bool {
        self.depth == other.depth
            && match (&self.root, &other.root) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    Arc::ptr_eq(a, b)
                        || matches!((a.as_ref(), b.as_ref()),
                (Node::Retained(a), Node::Retained(b)) if a == b)
                }
                _ => false,
            }
    }
    pub(super) fn get(
        &self,
        page: usize,
        reader: Option<&Arc<RetainedContext>>,
        budget: Option<&JobBudget>,
    ) -> Result<Option<Arc<Leaf>>> {
        check(budget)?;
        if page >= span(self.depth)? {
            return Ok(None);
        }
        let mut node = self.root.clone();
        let mut base = 0;
        for depth in (1..=self.depth).rev() {
            let Some(current) = node else {
                return Ok(None);
            };
            let stride = span(depth - 1)?;
            let slot = (page - base) / stride;
            node = branch(&current, depth, base, reader, budget)?[slot].clone();
            base += slot * stride;
        }
        check(budget)?;
        match node.as_deref() {
            None => Ok(None),
            Some(Node::Leaf(leaf)) => Ok(Some(leaf.clone())),
            Some(Node::Retained(id)) => Ok(Some(Arc::new(Leaf::Retained(*id)))),
            _ => Err(Error::Unavailable("ancestry directory leaf kind")),
        }
    }
    pub(super) fn set(
        &mut self,
        page: usize,
        leaf: Arc<Leaf>,
        reader: Option<&Arc<RetainedContext>>,
    ) -> Result<()> {
        // Stage growth and all fallible path reads before mutating this root.
        let mut next = self.clone();
        while page >= span(next.depth)? {
            // Empty growth changes only the coordinate depth. Wrapping None
            // would retain an empty lower branch on a later sparse insert;
            // readers correctly refuse such a noncanonical branch.
            if let Some(root) = next.root.take() {
                let mut children = std::array::from_fn(|_| None);
                children[0] = Some(root);
                next.root = Some(Arc::new(Node::Branch(children)));
            }
            next.depth = next
                .depth
                .checked_add(1)
                .ok_or(Error::Unavailable("ancestry directory depth"))?;
        }
        next.root = Some(Self::replace(
            next.root.as_ref(),
            next.depth,
            0,
            page,
            leaf,
            reader,
        )?);
        *self = next;
        Ok(())
    }
    fn replace(
        node: Option<&Arc<Node>>,
        depth: usize,
        base: usize,
        page: usize,
        leaf: Arc<Leaf>,
        reader: Option<&Arc<RetainedContext>>,
    ) -> Result<Arc<Node>> {
        if depth == 0 {
            return Ok(Arc::new(Node::Leaf(leaf)));
        }
        let mut children = match node {
            None => std::array::from_fn(|_| None),
            Some(node) => branch(node, depth, base, reader, None)?,
        };
        let stride = span(depth - 1)?;
        let slot = (page - base) / stride;
        children[slot] = Some(Self::replace(
            children[slot].as_ref(),
            depth - 1,
            base + slot * stride,
            page,
            leaf,
            reader,
        )?);
        Ok(Arc::new(Node::Branch(children)))
    }
    pub(super) fn visit(
        &self,
        reader: Option<&Arc<RetainedContext>>,
        budget: Option<&JobBudget>,
        visit: &mut impl FnMut(usize, Arc<Leaf>) -> Result<()>,
    ) -> Result<()> {
        if let Some(root) = &self.root {
            Self::walk(root, self.depth, 0, reader, budget, visit)?;
        }
        check(budget)
    }
    fn walk(
        node: &Arc<Node>,
        depth: usize,
        base: usize,
        reader: Option<&Arc<RetainedContext>>,
        budget: Option<&JobBudget>,
        visit: &mut impl FnMut(usize, Arc<Leaf>) -> Result<()>,
    ) -> Result<()> {
        check(budget)?;
        if depth == 0 {
            return match node.as_ref() {
                Node::Leaf(leaf) => visit(base, leaf.clone()),
                Node::Retained(id) => visit(base, Arc::new(Leaf::Retained(*id))),
                _ => Err(Error::Unavailable("ancestry directory leaf kind")),
            };
        }
        let stride = span(depth - 1)?;
        let children = branch(node, depth, base, reader, budget)?;
        for (slot, child) in children.iter().enumerate() {
            if let Some(child) = child {
                Self::walk(
                    child,
                    depth - 1,
                    base + slot * stride,
                    reader,
                    budget,
                    visit,
                )?;
            }
        }
        check(budget)
    }
    pub(super) fn retain(
        &self,
        store: &mut Store,
        reader: &Arc<RetainedContext>,
        budget: &JobBudget,
        retain_leaf: &mut impl FnMut(usize, &Arc<Leaf>, &mut Store) -> Result<Digest>,
    ) -> Result<Self> {
        let root = self
            .root
            .as_ref()
            .map(|root| Self::retain_node(root, self.depth, 0, store, reader, budget, retain_leaf))
            .transpose()?;
        Ok(Self {
            root,
            depth: self.depth,
        })
    }
    fn retain_node(
        node: &Arc<Node>,
        depth: usize,
        base: usize,
        store: &mut Store,
        reader: &Arc<RetainedContext>,
        budget: &JobBudget,
        retain_leaf: &mut impl FnMut(usize, &Arc<Leaf>, &mut Store) -> Result<Digest>,
    ) -> Result<Arc<Node>> {
        budget.check()?;
        // A live receiver-minted unchanged subtree is shared, not a cold
        // acceptance shortcut. Every later lookup/walk freshly qualifies it.
        if matches!(node.as_ref(), Node::Retained(_)) {
            return Ok(node.clone());
        }
        if depth == 0 {
            let Node::Leaf(leaf) = node.as_ref() else {
                return Err(Error::Unavailable("ancestry directory leaf kind"));
            };
            return Ok(Arc::new(Node::Retained(retain_leaf(base, leaf, store)?)));
        }
        let children = branch(node, depth, base, Some(reader), Some(budget))?;
        let stride = span(depth - 1)?;
        let mut bytes = Vec::with_capacity(SIZE);
        bytes.extend_from_slice(b"SNF04AD2");
        bytes.extend_from_slice(&reader.domain());
        bytes.extend_from_slice(&(base as u64).to_le_bytes());
        bytes
            .push(u8::try_from(depth).map_err(|_| Error::Unavailable("ancestry directory depth"))?);
        bytes.extend_from_slice(&[0; 7]);
        for (slot, child) in children.iter().enumerate() {
            match child {
                None => bytes.extend_from_slice(&[0; 33]),
                Some(child) => {
                    let child = Self::retain_node(
                        child,
                        depth - 1,
                        base + slot * stride,
                        store,
                        reader,
                        budget,
                        retain_leaf,
                    )?;
                    let Node::Retained(id) = child.as_ref() else {
                        return Err(Error::Unavailable("ancestry directory retention"));
                    };
                    bytes.push(1);
                    bytes.extend_from_slice(id);
                }
            }
        }
        budget.source()?;
        let id = store.retain_ancestry_directory_page(&bytes)?;
        budget.check()?;
        Ok(Arc::new(Node::Retained(id)))
    }
    pub(super) fn directory_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; 34];
        match self.root.as_deref() {
            None => {}
            Some(Node::Retained(id)) => {
                bytes[0] = self.depth as u8;
                bytes[1] = 1;
                bytes[2..].copy_from_slice(id);
            }
            _ => return Err(Error::Unavailable("directory requires disk ancestry")),
        }
        Ok(bytes)
    }
    pub(super) fn from_directory(bytes: &[u8], page_limit: usize) -> Result<Self> {
        if bytes.len() != 34 {
            return Err(Error::Unavailable("ancestry directory length"));
        }
        let depth = bytes[0] as usize;
        let mut max_depth = 0;
        while span(max_depth)? < page_limit {
            max_depth += 1;
        }
        if depth > max_depth {
            return Err(Error::Unavailable("ancestry directory depth"));
        }
        match bytes[1] {
            0 if bytes.iter().all(|b| *b == 0) => Ok(Self::default()),
            1 => Ok(Self {
                depth,
                root: Some(Arc::new(Node::Retained(
                    bytes[2..]
                        .try_into()
                        .map_err(|_| Error::Unavailable("ancestry directory address"))?,
                ))),
            }),
            _ => Err(Error::Unavailable("ancestry directory kind")),
        }
    }
}
