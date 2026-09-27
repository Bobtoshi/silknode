//! At most current and next immutable configurations under one role/journal owner.
use crate::{Digest, Error, Result, config::SignedConfig, tls::Transport};
use std::{cell::RefCell, rc::Rc};

pub type Link = Rc<RefCell<Transport>>;
pub fn link(transport: Transport) -> Link {
    Rc::new(RefCell::new(transport))
}

pub trait Configured {
    fn config(&self) -> &SignedConfig;
}
pub struct Epochs<T> {
    entries: [Option<T>; 2],
}
impl<T: Configured> Epochs<T> {
    pub(crate) const fn new(current: T) -> Self {
        Self {
            entries: [Some(current), None],
        }
    }
    pub(crate) fn for_round(&self, round: u64) -> Result<&T> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.config().contains_round(round))
            .ok_or(Error::Unavailable("owner round has no installed epoch"))
    }
    pub(crate) fn for_round_mut(&mut self, round: u64) -> Result<&mut T> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.config().contains_round(round))
            .ok_or(Error::Unavailable("owner round has no installed epoch"))
    }
    pub(crate) fn check_next(&self, config: &SignedConfig) -> Result<()> {
        let latest = self
            .entries
            .iter()
            .flatten()
            .max_by_key(|e| e.config().epoch())
            .ok_or(Error::Unavailable("owner epoch missing"))?
            .config();
        if self.entries.iter().all(Option::is_some)
            || latest.domain() != config.domain()
            || latest.cohort() != config.cohort()
            || latest.epoch().checked_add(1) != Some(config.epoch())
        {
            return Err(Error::Unavailable("owner next epoch context/capacity"));
        }
        Ok(())
    }
    pub(crate) fn install(&mut self, next: T) -> Result<()> {
        self.check_next(next.config())?;
        *self
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .expect("checked epoch capacity") = Some(next);
        Ok(())
    }
    pub(crate) fn retire(&mut self, highest: Option<u64>, live: [Option<Digest>; 2]) {
        let Some(newest) = self
            .entries
            .iter()
            .flatten()
            .map(|e| e.config().epoch())
            .max()
        else {
            return;
        };
        if highest.is_none_or(|r| r / 2880 < u64::from(newest)) {
            return;
        }
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|e| {
                e.config().epoch() < newest && !live.contains(&Some(e.config().id()))
            }) {
                *slot = None;
            }
        }
    }
    pub(crate) fn contains(&self, id: Digest) -> bool {
        self.entries.iter().flatten().any(|e| e.config().id() == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Epoch(SignedConfig);
    impl Configured for Epoch {
        fn config(&self) -> &SignedConfig {
            &self.0
        }
    }
    #[test]
    fn lifecycle_epoch_pool_retains_old_live_config_without_resetting_admission() {
        let old = crate::tests::epoch_config(2);
        let old_id = old.id();
        let next = crate::tests::epoch_config(3);
        let next_id = next.id();
        let later = crate::tests::epoch_config(4);
        let mut epochs = Epochs::new(Epoch(old));
        assert!(epochs.check_next(&later).is_err());
        epochs.install(Epoch(next)).unwrap();
        assert!(epochs.check_next(&later).is_err());
        assert_eq!(epochs.for_round(8639).unwrap().config().id(), old_id);
        assert_eq!(epochs.for_round(8640).unwrap().config().id(), next_id);
        // A prepared next epoch alone cannot retire a still-needed old epoch.
        epochs.retire(Some(8638), [None, None]);
        assert!(epochs.contains(old_id));
        // Global new-first admission may overlap the actual old-final actor.
        epochs.retire(Some(8640), [Some(old_id), Some(next_id)]);
        assert!(epochs.contains(old_id));
        epochs.retire(Some(8640), [None, Some(next_id)]);
        assert!(!epochs.contains(old_id));
        assert!(epochs.for_round(8639).is_err());
        epochs.install(Epoch(later)).unwrap();
        assert!(epochs.for_round(11520).is_ok());
        assert!(epochs.for_round(14400).is_err());
    }
}
