//! One durable exact manifest proposal, bound to locally verified cut authority.
use crate::{
    Digest, Error, Result,
    config::SignedConfig,
    control::{Kind, Role, SignedControl},
    manifest::SignedManifest,
    owner::{DurableJournal, Identity, PinRetention, prefix},
    schedule::Schedule,
};
use silk_f04_node::{genesis::Genesis, node::Node, state::BranchState};
use std::rc::Rc;

/// Selected exact local cut for ONE round.
///
/// No public-Cut/peer-root constructor or deserializer exists.
/// A nonzero selection holds the READY node immutably until
/// negotiation ends, so an in-process reorg cannot silently stale its authority.
pub struct SelectedCut<'a> {
    body: [u8; 128],
    config: Digest,
    _node: Option<&'a Node>,
    _genesis: Option<&'a Genesis>,
    _owned_node: Option<Rc<Node>>,
    _owned_genesis: Option<Rc<Genesis>>,
}
impl<'a> SelectedCut<'a> {
    /// Select an existing eligible catalog entry from an immutable READY node.
    /// # Errors
    /// Refuses foreign N, wrong epoch, unavailable history, orphaned/immature cut.
    pub fn from_ready_node(
        node: &'a Node,
        config: &SignedConfig,
        round: u64,
        index: u64,
    ) -> Result<Self> {
        let state = node.state()?;
        if index > state.eligible_cut().index {
            return Err(Error::Invalid("immature relay cut"));
        }
        let cut = usize::try_from(index)
            .ok()
            .and_then(|i| state.cuts().get(i))
            .ok_or(Error::Invalid("missing relay cut"))?;
        Ok(Self {
            body: selected_body(
                config,
                round,
                node.genesis().domain(),
                cut.index,
                cut.id,
                cut.root,
            )?,
            config: config.id(),
            _node: Some(node),
            _genesis: None,
            _owned_node: None,
            _owned_genesis: None,
        })
    }
    /// Derive only cut zero from fully admitted public genesis using the existing
    /// reducer. No `RandomX` VM, proving arrays or arbitrary decoded root is needed.
    /// # Errors
    /// Refuses foreign N, epoch or genesis reducer failure.
    pub fn from_genesis(genesis: &'a Genesis, config: &SignedConfig, round: u64) -> Result<Self> {
        let state = BranchState::genesis(genesis)?;
        let cut = state
            .cuts()
            .first()
            .ok_or(Error::Unavailable("genesis cut missing"))?;
        Ok(Self {
            body: selected_body(config, round, genesis.domain(), cut.index, cut.id, cut.root)?,
            config: config.id(),
            _node: None,
            _genesis: Some(genesis),
            _owned_node: None,
            _owned_genesis: None,
        })
    }
    fn check(&self, config: &SignedConfig, schedule: &Schedule) -> Result<()> {
        if self.config != config.id() {
            return Err(Error::Invalid("selected cut configuration"));
        }
        crate::manifest::check_body(&self.body, config, schedule.round())
    }
    fn into_body(self) -> [u8; 128] {
        self.body
    }
    /// A failed B negotiation may reserve ONLY its retained actual local cut.
    /// This returns no manifested/authorization capability and signs no proposal.
    pub(crate) fn abort_b<P: PinRetention>(
        self,
        config: &SignedConfig,
        schedule: &Schedule,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        utc_round: u64,
    ) -> Result<crate::owner::LiveCancel> {
        self.check(config, schedule)?;
        identity.check(config, Role::B)?;
        journal.check_role(Role::B)?;
        schedule.clock_healthy()?;
        schedule.in_window(-10_000_000_000, 22_000_000_000)?;
        if journal.decision(schedule.round()).is_none() {
            journal.update(|j| j.begin(config, schedule.round(), &self.body, utc_round))?;
        }
        journal.cancel_live(config, schedule, identity)
    }
    /// Admit actual received co-signed bytes against this immutable local cut.
    /// The receiving role must still enforce its original completion barrier.
    /// # Errors
    /// Refuses foreign context, bad signatures or any local-cut mismatch.
    pub fn admit_signed(
        self,
        bytes: &[u8],
        config: &SignedConfig,
        schedule: &Schedule,
    ) -> Result<SignedManifest> {
        self.check(config, schedule)?;
        let manifest = SignedManifest::verify(bytes, config, schedule.round())?;
        if manifest.bytes()[..128] != self.into_body() {
            return Err(Error::Invalid("received manifest/local cut mismatch"));
        }
        Ok(manifest)
    }
    /// Admit the same exact locally selected cut under the separate IM3 round
    /// mapping. No clock, proof, custody or execution authority is inferred.
    #[cfg(feature = "aip2-preparation")]
    pub fn admit_im3_signed(
        &self,
        bytes: &[u8],
        config: &SignedConfig,
        schedule: &crate::im3_schedule::Im3Schedule,
    ) -> Result<SignedManifest> {
        if self.config != config.id() {
            return Err(Error::Invalid("selected cut configuration"));
        }
        crate::manifest::check_body(&self.body, config, schedule.round())?;
        let manifest = SignedManifest::verify(bytes, config, schedule.round())?;
        if manifest.bytes()[..128] != self.body {
            return Err(Error::Invalid("received manifest/local cut mismatch"));
        }
        Ok(manifest)
    }
}
impl SelectedCut<'static> {
    /// Retain an immutable READY node owner through asynchronous negotiation.
    /// The shared owner prevents mutable node access/reorg until this cut closes.
    /// # Errors
    /// Applies exactly the borrowed READY-node cut admission.
    pub fn from_owned_ready_node(
        node: Rc<Node>,
        config: &SignedConfig,
        round: u64,
        index: u64,
    ) -> Result<Self> {
        let body = SelectedCut::from_ready_node(&node, config, round, index)?.body;
        Ok(Self {
            body,
            config: config.id(),
            _node: None,
            _genesis: None,
            _owned_node: Some(node),
            _owned_genesis: None,
        })
    }
    /// Retain admitted genesis authority for asynchronous cut-zero negotiation.
    /// # Errors
    /// Applies exactly the borrowed genesis/reducer admission.
    pub fn from_owned_genesis(
        genesis: Rc<Genesis>,
        config: &SignedConfig,
        round: u64,
    ) -> Result<Self> {
        let body = SelectedCut::from_genesis(&genesis, config, round)?.body;
        Ok(Self {
            body,
            config: config.id(),
            _node: None,
            _genesis: None,
            _owned_node: None,
            _owned_genesis: Some(genesis),
        })
    }
}
fn selected_body(
    config: &SignedConfig,
    round: u64,
    domain: Digest,
    index: u64,
    id: Digest,
    root: Digest,
) -> Result<[u8; 128]> {
    if config.domain() != domain || !config.contains_round(round) {
        return Err(Error::Invalid("selected local cut context"));
    }
    let mut body = [0; 128];
    body[..8].copy_from_slice(b"SNRNDF03");
    body[8..40].copy_from_slice(&domain);
    body[40..44].copy_from_slice(&config.cohort().to_le_bytes());
    body[44..52].copy_from_slice(&round.to_le_bytes());
    body[52..60].copy_from_slice(&index.to_le_bytes());
    body[60..92].copy_from_slice(&id);
    body[92..124].copy_from_slice(&root);
    Ok(body)
}

/// Exact A proposal created only after durable reservation of that unsigned M.
pub struct AProposal<'a> {
    cut: SelectedCut<'a>,
    control: SignedControl,
}
impl<'a> AProposal<'a> {
    /// Persist M before either local signature in the fixed proposal phase.
    /// The outer coordinator owns actual scheduled transport and resource caps.
    /// # Errors
    /// Any cut/key/clock/durability/signature/deadline failure creates no proposal.
    pub fn begin<P: PinRetention>(
        cut: SelectedCut<'a>,
        config: &SignedConfig,
        schedule: &Schedule,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        utc_round: u64,
    ) -> Result<Self> {
        schedule.in_window(-10_000_000_000, -9_000_000_000)?;
        schedule.clock_healthy()?;
        cut.check(config, schedule)?;
        identity.check(config, Role::A)?;
        journal.check_role(Role::A)?;
        journal.update(|j| j.begin(config, schedule.round(), &cut.body, utc_round))?;
        let control = manifest_control(config, schedule, identity, Kind::ManifestA, &cut.body)?;
        schedule.completed_before(-9_000_000_000)?;
        Ok(Self { cut, control })
    }
    /// Nonsecret proposal; only the driver's fixed -10 control slot may send it.
    #[must_use]
    pub const fn control(&self) -> &SignedControl {
        &self.control
    }
    /// Admit B's actual control, require identical M, and durably bind both signatures.
    /// # Errors
    /// Refuses early/late, conflicting, invalid or nondurable negotiation.
    pub fn finish<P: PinRetention>(
        self,
        bytes: &[u8],
        config: &SignedConfig,
        schedule: &Schedule,
        journal: &mut DurableJournal<P>,
    ) -> Result<Manifested> {
        schedule.in_window(-10_000_000_000, -8_000_000_000)?;
        schedule.clock_healthy()?;
        self.cut.check(config, schedule)?;
        journal.check_role(Role::A)?;
        let b = SignedControl::verify(bytes, config, schedule.round(), Kind::ManifestB, Role::B)?;
        if b.bytes()[10] != 1 || b.bytes()[88..216] != self.cut.body {
            return Err(Error::Invalid("conflicting negotiated manifest"));
        }
        let manifest = assemble(config, schedule, &self.control, &b)?;
        schedule.completed_before(-8_000_000_000)?;
        journal.update(|j| j.manifested(&manifest))?;
        schedule.completed_before(-8_000_000_000)?;
        Ok(Manifested { manifest })
    }
}

/// Locally cut-checked, co-signed and durably bound manifest. This still does not
/// prove downstream delivery, clock qualification, custody or native resource caps.
pub struct Manifested {
    manifest: SignedManifest,
}
impl Manifested {
    // Synthetic signed context for local TLS/collection tests only. This bypasses
    // native cut/durability admission and exists in no production build.
    #[cfg(test)]
    pub(crate) fn input_fixture(manifest: SignedManifest) -> Self {
        Self { manifest }
    }
    /// B validates A's nested/outer signatures, persists the same M, then signs.
    /// # Errors
    /// Refuses wrong cut/key/phase, conflict, journal or signature failure.
    pub fn answer<P: PinRetention>(
        cut: SelectedCut<'_>,
        bytes: &[u8],
        config: &SignedConfig,
        schedule: &Schedule,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        utc_round: u64,
    ) -> Result<(SignedControl, Self)> {
        let result =
            Self::answer_selected(&cut, bytes, config, schedule, identity, journal, utc_round);
        drop(cut); // Public one-shot API consumes its immutable selection even on error.
        result
    }
    pub(crate) fn answer_selected<P: PinRetention>(
        cut: &SelectedCut<'_>,
        bytes: &[u8],
        config: &SignedConfig,
        schedule: &Schedule,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        utc_round: u64,
    ) -> Result<(SignedControl, Self)> {
        schedule.in_window(-10_000_000_000, -9_000_000_000)?;
        schedule.clock_healthy()?;
        cut.check(config, schedule)?;
        identity.check(config, Role::B)?;
        journal.check_role(Role::B)?;
        let body = cut.body;
        let a = SignedControl::verify(bytes, config, schedule.round(), Kind::ManifestA, Role::A)?;
        if a.bytes()[10] != 1 || a.bytes()[88..216] != body {
            return Err(Error::Invalid("B local cut/proposal mismatch"));
        }
        journal.update(|j| j.begin(config, schedule.round(), &body, utc_round))?;
        let b = manifest_control(config, schedule, identity, Kind::ManifestB, &body)?;
        let manifest = assemble(config, schedule, &a, &b)?;
        schedule.completed_before(-9_000_000_000)?;
        journal.update(|j| j.manifested(&manifest))?;
        schedule.completed_before(-9_000_000_000)?;
        Ok((b, Self { manifest }))
    }
    /// Same immutable full bytes for every client/producer downlink.
    #[must_use]
    pub const fn manifest(&self) -> &SignedManifest {
        &self.manifest
    }
}
fn manifest_control(
    config: &SignedConfig,
    schedule: &Schedule,
    identity: &Identity,
    kind: Kind,
    manifest: &[u8; 128],
) -> Result<SignedControl> {
    let mut body = prefix(config, schedule.round(), [0; 32]);
    body[88..216].copy_from_slice(manifest);
    body[216..280].copy_from_slice(&identity.manifest_signature(config, manifest)?);
    identity.control(config, schedule.round(), kind, &body)
}
fn assemble(
    config: &SignedConfig,
    schedule: &Schedule,
    a: &SignedControl,
    b: &SignedControl,
) -> Result<SignedManifest> {
    let mut bytes = [0; 256];
    bytes[..128].copy_from_slice(&a.bytes()[88..216]);
    bytes[128..192].copy_from_slice(&a.bytes()[216..280]);
    bytes[192..256].copy_from_slice(&b.bytes()[216..280]);
    SignedManifest::verify(&bytes, config, schedule.round())
}
