//! One process-lifetime role socket/setup ledger. Native RSS/CPU limits are separate.
use crate::{Error, Result, control::Role};
use std::{
    cell::Cell,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

static OWNED: AtomicBool = AtomicBool::new(false);
struct Root;
impl Drop for Root {
    fn drop(&mut self) {
        OWNED.store(false, Ordering::Release);
    }
}
struct State {
    role: Role,
    sockets: Cell<u8>,
    setups: Cell<u8>,
    _root: Root,
}

/// One role's process-wide socket and simultaneous-setup accounting. Cloning
/// shares all counters; a second root is refused while any permit survives.
///
/// This does not attest TLS library memory, native RSS or lifecycle timing.
#[derive(Clone)]
pub struct RoleResources(Rc<State>);
impl RoleResources {
    /// Reserve the sole resource root before creating bounded listeners/sockets.
    /// # Errors
    /// Refuses another live role root anywhere in the process.
    pub fn new(role: Role) -> Result<Self> {
        OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Unavailable("relay resource root already owned"))?;
        Ok(Self(Rc::new(State {
            role,
            sockets: Cell::new(0),
            setups: Cell::new(0),
            _root: Root,
        })))
    }
    /// Actual configured role; never a peer-supplied identity.
    #[must_use]
    pub fn role(&self) -> Role {
        self.0.role
    }
    /// Count of still-owned descriptors, including quarantined connections.
    #[must_use]
    pub fn sockets(&self) -> u8 {
        self.0.sockets.get()
    }
    /// Pending TCP/TLS/Join owners across all windows of this role.
    #[must_use]
    pub fn pending_setups(&self) -> u8 {
        self.0.setups.get()
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn adopt(role: Role, transport: &mut crate::tls::Transport) -> Result<Self> {
        let resources = match transport.resources() {
            Some(root) => root,
            None => Self::new(role)?,
        };
        if resources.role() != role {
            return Err(Error::Unavailable("relay resource role"));
        }
        transport.account(&resources)?;
        Ok(resources)
    }
    pub(crate) fn socket(&self) -> Result<SocketPermit> {
        let cap = match self.0.role {
            Role::A => 72,
            Role::B => 12,
            _ => 8,
        };
        let count = self.0.sockets.get();
        if count >= cap {
            return Err(Error::Unavailable("relay role socket cap"));
        }
        self.0.sockets.set(count + 1);
        Ok(SocketPermit(self.clone()))
    }
    pub(crate) fn setup(&self) -> Result<SetupPermit> {
        let count = self.0.setups.get();
        if count >= 2 {
            return Err(Error::Unavailable("relay two pending setups"));
        }
        self.0.setups.set(count + 1);
        Ok(SetupPermit(self.clone()))
    }
}
pub(crate) struct SocketPermit(RoleResources);
impl SocketPermit {
    pub(crate) const fn resources(&self) -> &RoleResources {
        &self.0
    }
}
impl Drop for SocketPermit {
    fn drop(&mut self) {
        self.0.0.sockets.set(self.0.0.sockets.get() - 1);
    }
}
pub(crate) struct SetupPermit(RoleResources);
impl Drop for SetupPermit {
    fn drop(&mut self) {
        self.0.0.setups.set(self.0.0.setups.get() - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_shared_caps_and_root_survive_original_owner_drop() {
        for (role, cap) in [(Role::A, 72), (Role::B, 12), (Role::P0, 8)] {
            let resources = RoleResources::new(role).unwrap();
            let clone = resources.clone();
            let mut sockets: Vec<_> = (0..cap).map(|_| resources.socket().unwrap()).collect();
            assert_eq!(resources.sockets(), cap);
            assert!(clone.socket().is_err());
            let first = clone.setup().unwrap();
            let second = resources.setup().unwrap();
            assert_eq!(clone.pending_setups(), 2);
            assert!(resources.setup().is_err());
            assert!(RoleResources::new(role).is_err());
            drop(resources);
            assert_eq!(clone.sockets(), cap);
            drop(first);
            assert_eq!(clone.pending_setups(), 1);
            let replacement = clone.setup().unwrap();
            drop(second);
            drop(replacement);
            sockets.pop();
            assert_eq!(clone.sockets(), cap - 1);
            sockets.push(clone.socket().unwrap());
            drop(clone);
            assert!(RoleResources::new(role).is_err()); // Socket permits keep the root alive.
            drop(sockets);
            let fresh = RoleResources::new(role).unwrap();
            assert_eq!(fresh.sockets(), 0);
            assert_eq!(fresh.pending_setups(), 0);
            drop(fresh);
        }
    }
}
