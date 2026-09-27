//! Live signing/persistence owners, not peer-provided readiness flags.
use crate::{
    Digest, Error, Result,
    config::SignedConfig,
    control::{Kind, Role, SignedControl},
    journal::Journal,
    message,
};
use ed25519_dalek::SigningKey;
use silk_f04_node::auth::sign_role;
use std::rc::Rc;
use zeroize::Zeroizing;

/// Immutable, durably negotiated context shared by one coordinator's round
/// phases.
///
/// Owning the manifest and schedule avoids self-referential actors;
/// cloning this handle cannot create another schedule or reset its native lease.
pub struct ManifestRound {
    pub(crate) config: Rc<SignedConfig>,
    manifested: crate::negotiation::Manifested,
    pub(crate) schedule: Rc<crate::schedule::Schedule>,
}
impl ManifestRound {
    /// Bind the already locally cut-checked, durably negotiated manifest to its
    /// original immutable schedule. This creates no transport or signing permit.
    /// # Errors
    /// Refuses a different config, epoch or round.
    pub fn new(
        config: Rc<SignedConfig>,
        manifested: crate::negotiation::Manifested,
        schedule: Rc<crate::schedule::Schedule>,
    ) -> Result<Rc<Self>> {
        crate::frame::RoundContext::new(&config, manifested.manifest())?;
        if manifested.manifest().round() != schedule.round() {
            return Err(Error::Invalid("owned manifested round/schedule"));
        }
        Ok(Rc::new(Self {
            config,
            manifested,
            schedule,
        }))
    }
    /// Exact co-signed manifest; no mutable or caller-fabricated access exists.
    #[must_use]
    pub const fn manifest(&self) -> &crate::manifest::SignedManifest {
        self.manifested.manifest()
    }
    pub(crate) fn context(&self) -> crate::frame::RoundContext<'_> {
        crate::frame::RoundContext {
            config: &self.config,
            manifest: self.manifest(),
        }
    }
}

/// One configured application signer. Its arbitrary signing operation is private
/// to the protocol driver; this type is not an independent-custody attestation.
pub struct Identity {
    key: SigningKey,
    role: Role,
    config: Digest,
}
impl Identity {
    /// Admit the exact local role key from separately controlled secret storage.
    /// # Errors
    /// Refuses a key not named for that fixed role in the co-signed configuration.
    pub fn new(key: SigningKey, role: Role, config: &SignedConfig) -> Result<Self> {
        if key.verifying_key().to_bytes() != config.endpoints()[role as usize].signing {
            return Err(Error::Unavailable("local role key/config mismatch"));
        }
        Ok(Self {
            key,
            role,
            config: config.id(),
        })
    }
    pub(crate) fn check(&self, config: &SignedConfig, role: Role) -> Result<()> {
        if self.role != role || self.config != config.id() {
            return Err(Error::Unavailable("local signing role/context"));
        }
        Ok(())
    }
    pub(crate) fn control(
        &self,
        config: &SignedConfig,
        round: u64,
        kind: Kind,
        body: &[u8; 448],
    ) -> Result<SignedControl> {
        self.check(config, self.role)?;
        let mut bytes = Zeroizing::new([0; 512]);
        bytes[..448].copy_from_slice(body);
        bytes[8] = kind as u8;
        bytes[9] = self.role as u8;
        let signed = Zeroizing::new(message("SilkNode-F0-control", &[&bytes[..448]]));
        bytes[448..].copy_from_slice(&sign_role(&self.key, &signed)?);
        SignedControl::verify(bytes.as_ref(), config, round, kind, self.role)
    }
    pub(crate) fn manifest_signature(
        &self,
        config: &SignedConfig,
        body: &[u8; 128],
    ) -> Result<[u8; 64]> {
        self.check(config, self.role)?;
        if !matches!(self.role, Role::A | Role::B) {
            return Err(Error::Unavailable("manifest signer role"));
        }
        Ok(sign_role(
            &self.key,
            &message("SilkNode-F0-round", &[&config.id(), body]),
        )?)
    }
}

/// Retain each exact journal pin outside that journal's rollback domain.
/// This interface cannot establish independent custody or hardware anti-rollback.
pub trait PinRetention {
    /// Complete durable retention before returning success. A lost/uncertain pin
    /// is a STOP, never permission to read and adopt the journal's latest bytes.
    /// # Errors
    /// Report any write/durability/continuity uncertainty.
    fn retain(&mut self, pin: Digest) -> Result<()>;
}

/// Live journal owner couples EVERY mutation to the required retained-pin update.
/// Uncertainty poisons this owner; none of its APIs recover a signing capability.
pub struct DurableJournal<P: PinRetention> {
    journal: Journal,
    pins: P,
    failed: bool,
}
impl<P: PinRetention> DurableJournal<P> {
    #[cfg(feature = "functional-lab")]
    pub(crate) fn functional_identity(&self) -> Result<(u64, u64)> {
        self.journal.functional_identity()
    }
    /// Wrap only an explicitly created or independently pinned reopened journal.
    /// # Errors
    /// Refuses if retaining the current exact generation cannot be completed.
    pub fn new(journal: Journal, mut pins: P) -> Result<Self> {
        pins.retain(journal.pin())?;
        Ok(Self {
            journal,
            pins,
            failed: false,
        })
    }
    /// Earliest permissible fresh round, not a resume capability.
    #[must_use]
    pub const fn earliest_round(&self) -> u64 {
        self.journal.earliest_round()
    }
    /// Public terminal evidence only; never sufficient for a new signed output.
    #[must_use]
    pub fn decision(&self, round: u64) -> Option<crate::journal::Decision> {
        self.journal.decision(round)
    }
    /// Abort a still-live reversible round and retain its exact pin BEFORE any
    /// CANCEL signature. Reopened terminal records cannot mint this capability.
    /// A cancellation is not permission to replace an already selected record.
    /// # Errors
    /// Refuses foreign/stale/irrevocable state, unhealthy time or uncertain pins.
    pub fn cancel_live(
        &mut self,
        config: &SignedConfig,
        schedule: &crate::schedule::Schedule,
        identity: &Identity,
    ) -> Result<LiveCancel> {
        self.check_role(self.journal.role())?;
        identity.check(config, self.journal.role())?;
        schedule.clock_healthy()?;
        schedule.completed_before(22_000_000_000)?;
        let mut manifest = None;
        self.update(|journal| {
            manifest = Some(journal.cancel_live(config, schedule.round())?);
            Ok(())
        })?;
        let mut body = prefix(
            config,
            schedule.round(),
            manifest.ok_or(Error::Unavailable("committed abort context absent"))?,
        );
        body[10] = 0;
        let control = identity.control(config, schedule.round(), Kind::Cancel, &body)?;
        schedule.completed_before(22_000_000_000)?;
        Ok(LiveCancel { control })
    }
    /// Retire only a terminal live slot after its original+22 cleanup barrier.
    /// The owning coordinator must drop secret round material before this call.
    /// # Errors
    /// Refuses early, recovered, foreign, nonterminal or uncertain continuity.
    pub fn retire_live(
        &mut self,
        config: &SignedConfig,
        schedule: &crate::schedule::Schedule,
    ) -> Result<()> {
        if std::time::Instant::now() < schedule.at(22_000_000_000)? {
            return Err(Error::Unavailable("live retirement before cleanup barrier"));
        }
        self.update(|journal| journal.retire_live(config, schedule.round()))
    }
    pub(crate) fn check_role(&self, role: Role) -> Result<()> {
        if self.failed || self.journal.role() != role {
            return Err(Error::Unavailable("live journal role/continuity mismatch"));
        }
        Ok(())
    }
    pub(crate) fn update(&mut self, apply: impl FnOnce(&mut Journal) -> Result<()>) -> Result<()> {
        if self.failed {
            return Err(Error::Unavailable("live journal pin continuity STOP"));
        }
        self.failed = true;
        apply(&mut self.journal)?;
        self.pins.retain(self.journal.pin())?;
        self.failed = false;
        Ok(())
    }
}

/// Exact live-abort control, not a reusable signing or transport-slot permit.
/// Its private construction depends on a successfully retained live journal pin.
pub struct LiveCancel {
    control: SignedControl,
}
impl LiveCancel {
    /// Exact bytes may fill only this sender's unselected failure-control slots.
    #[must_use]
    pub const fn control(&self) -> &SignedControl {
        &self.control
    }
    pub(crate) fn producer(
        config: &SignedConfig,
        schedule: &crate::schedule::Schedule,
        identity: &Identity,
        role: Role,
        manifest: Option<&crate::manifest::SignedManifest>,
    ) -> Result<Self> {
        if !matches!(role, Role::P0 | Role::P1 | Role::P2) {
            return Err(Error::Unavailable("producer failure signer"));
        }
        identity.check(config, role)?;
        schedule.clock_healthy()?;
        schedule.completed_before(22_000_000_000)?;
        let mut body = prefix(
            config,
            schedule.round(),
            manifest.map_or([0; 32], crate::manifest::SignedManifest::id),
        );
        body[10] = 0;
        Ok(Self {
            control: identity.control(config, schedule.round(), Kind::Cancel, &body)?,
        })
    }
}

pub(crate) fn prefix(config: &SignedConfig, round: u64, manifest: Digest) -> [u8; 448] {
    let mut body = [0; 448];
    body[..8].copy_from_slice(b"SNCTLF03");
    body[10] = 1;
    body[12..44].copy_from_slice(&config.domain());
    body[44..76].copy_from_slice(&config.id());
    body[76..80].copy_from_slice(&config.cohort().to_le_bytes());
    body[80..88].copy_from_slice(&round.to_le_bytes());
    body[88..120].copy_from_slice(&manifest);
    body
}
