//! Fixed-window, original-lease TCP/TLS/Join setup. Candidates have no old-round authority.
use crate::{
    Digest, Error, Result,
    config::{CONFIG_BYTES, Roster, SignedConfig},
    control::Role,
    driver::RoundLease,
    input::{AdmittedSession, Enrolling, Enrollment, Sessions},
    resources::{RoleResources, SetupPermit},
    schedule::QualifiedClockSample,
    tls::{ClientProfile, ConnectStep, Connecting, Listener, Setup, SetupStep, Transport},
};
use std::{cell::Cell, rc::Rc, time::Instant};

/// Read-only functional-fixture evidence, never an admission capability.
#[cfg(feature = "functional-lab")]
#[derive(Debug, PartialEq, Eq)]
pub struct FunctionalOwnerSnapshot {
    /// Original fresh-start floor; epoch promotion must not reset it.
    pub floor: u64,
    /// Process-wide highest admission, including old epochs.
    pub highest: Option<u64>,
    /// Actual retained journal lock device/inode; producers have no relay journal.
    pub journal: Option<(u64, u64)>,
    /// Actual live round, configuration and hop-transport identities.
    pub live: [Option<FunctionalRoundSnapshot>; 2],
}

/// Actual actor's snapshotted links, not future epoch defaults.
#[cfg(feature = "functional-lab")]
#[derive(Debug, PartialEq, Eq)]
pub struct FunctionalRoundSnapshot {
    /// Original admitted round.
    pub round: u64,
    /// Exact configuration digest.
    pub config: Digest,
    /// A/P use the first entry; B uses A then P0/P1/P2; unused entries are zero.
    pub hops: [u64; 4],
}

/// Which fixed lifecycle window produced a connection. Neither rescues old keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupPurpose {
    /// Same-configuration repair at +24..+28, eligible no earlier than r+2.
    Maintenance,
    /// Next-epoch setup at first-60..first-30 under the original q-2 round lease.
    NextEpoch,
}
struct Seal {
    config: Rc<SignedConfig>,
    resources: RoleResources,
    purpose: SetupPurpose,
    eligible: u64,
    complete: Cell<bool>,
    failed: Cell<bool>,
}
struct WindowState {
    seal: Rc<Seal>,
    roster: Option<Rc<Roster>>,
    allowed_hops: u8,
    allowed_clients: u32,
    attempted_hops: Cell<u8>,
    accepted_clients: Cell<u8>,
    joined_clients: Cell<u32>,
    pending: Rc<Cell<u8>>,
    start: i64,
    end: i64,
    // Last: every pending socket/buffer must drop before the original timer lease.
    lease: Rc<RoundLease>,
}
impl WindowState {
    fn check(&self) -> Result<()> {
        self.lease.check()?;
        self.lease.schedule.clock_healthy()?;
        self.lease.schedule.in_window(self.start, self.end)?;
        if self.seal.failed.get() || self.seal.complete.get() {
            return Err(Error::Unavailable("setup window closed/failed"));
        }
        Ok(())
    }
    fn deadline(&self) -> Result<Instant> {
        self.lease.schedule.at(self.end)
    }
    fn pending(&self) -> Result<PendingPermit> {
        let native = self.seal.resources.setup()?;
        self.pending.set(self.pending.get() + 1);
        Ok(PendingPermit {
            _native: native,
            count: Rc::clone(&self.pending),
        })
    }
    fn claim_hop(&self, role: Role) -> Result<()> {
        let bit = 1 << (role as u8);
        if self.allowed_hops & bit == 0 || self.attempted_hops.get() & bit != 0 {
            return Err(Error::Unavailable(
                "setup endpoint unavailable/already attempted",
            ));
        }
        self.attempted_hops.set(self.attempted_hops.get() | bit);
        Ok(())
    }
}
struct PendingPermit {
    _native: SetupPermit,
    count: Rc<Cell<u8>>,
}
impl Drop for PendingPermit {
    fn drop(&mut self) {
        self.count.set(self.count.get() - 1);
    }
}

/// A one-use window obtained only from an actual role owner's live round slot.
///
/// Keep polling pending attempts and finish/drop this window before its deadline;
/// retaining it past the native +30 deadline deliberately retains that kill timer.
pub struct SetupWindow {
    prepared: Option<PreparedConnections>,
    state: Rc<WindowState>,
}
impl Drop for SetupWindow {
    fn drop(&mut self) {
        if !self.state.seal.complete.get() {
            self.state.seal.failed.set(true);
        }
    }
}
impl SetupWindow {
    pub(crate) fn maintenance(lease: Rc<RoundLease>, hops: u8, clients: u32) -> Result<Self> {
        lease.check()?;
        lease.schedule.clock_healthy()?;
        lease.schedule.completed_before(28_000_000_000)?;
        if lease.maintenance_claimed.replace(true) {
            return Err(Error::Unavailable("maintenance window already claimed"));
        }
        let eligible = lease
            .schedule
            .round()
            .checked_add(2)
            .filter(|r| lease.config.contains_round(*r))
            .ok_or(Error::Unavailable("maintenance eligibility crosses epoch"))?;
        let config = Rc::clone(&lease.config);
        Ok(Self::new(
            lease,
            config,
            SetupPurpose::Maintenance,
            eligible,
            hops,
            clients,
            24_000_000_000,
            28_000_000_000,
        ))
    }
    pub(crate) fn epoch(
        lease: Rc<RoundLease>,
        bytes: &[u8; CONFIG_BYTES],
        roots: [Digest; 2],
    ) -> Result<Self> {
        lease.check()?;
        lease.schedule.clock_healthy()?;
        lease.schedule.in_window(0, 30_000_000_000)?;
        let epoch = lease
            .config
            .epoch()
            .checked_add(1)
            .ok_or(Error::Unavailable("next epoch overflow"))?;
        let first = u64::from(epoch) * 2880;
        if lease.schedule.round().checked_add(2) != Some(first) || lease.epoch_claimed.replace(true)
        {
            return Err(Error::Unavailable(
                "next epoch original window mapping/reuse",
            ));
        }
        // Phase and one-use claim precede all signature/role-key work.
        let config = Rc::new(SignedConfig::verify(
            bytes,
            lease.config.domain(),
            lease.config.cohort(),
            epoch,
            roots,
        )?);
        lease.check()?;
        lease.schedule.in_window(0, 30_000_000_000)?;
        let (hops, clients) = match lease.resources.role() {
            Role::A => (1 << Role::B as u8, u32::MAX),
            Role::B => (
                (1 << Role::A as u8)
                    | (1 << Role::P0 as u8)
                    | (1 << Role::P1 as u8)
                    | (1 << Role::P2 as u8),
                0,
            ),
            _ => (1 << Role::B as u8, 0),
        };
        Ok(Self::new(
            lease,
            config,
            SetupPurpose::NextEpoch,
            first,
            hops,
            clients,
            0,
            30_000_000_000,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn new(
        lease: Rc<RoundLease>,
        config: Rc<SignedConfig>,
        purpose: SetupPurpose,
        eligible: u64,
        hops: u8,
        clients: u32,
        start: i64,
        end: i64,
    ) -> Self {
        let seal = Rc::new(Seal {
            config,
            resources: lease.resources.clone(),
            purpose,
            eligible,
            complete: Cell::new(false),
            failed: Cell::new(false),
        });
        Self {
            prepared: Some(PreparedConnections {
                seal: Rc::clone(&seal),
                hops: std::array::from_fn(|_| None),
                sessions: Vec::with_capacity(32),
            }),
            state: Rc::new(WindowState {
                seal,
                roster: None,
                allowed_hops: hops,
                allowed_clients: clients,
                attempted_hops: Cell::new(0),
                accepted_clients: Cell::new(0),
                joined_clients: Cell::new(0),
                pending: Rc::new(Cell::new(0)),
                start,
                end,
                lease,
            }),
        }
    }
    /// Exact already-verified target configuration, never the old round's replacement.
    #[must_use]
    pub fn config(&self) -> &SignedConfig {
        &self.state.seal.config
    }
    /// Shared role resource root, including current connections and listeners.
    #[must_use]
    pub fn resources(&self) -> RoleResources {
        self.state.seal.resources.clone()
    }
    /// Fixed start instant. Waiting for this does not reset the original CPU budget.
    /// # Errors
    /// Refuses an unrepresentable original schedule offset.
    pub fn starts_at(&self) -> Result<Instant> {
        self.state.lease.schedule.at(self.state.start)
    }
    /// Exact fixed end; no grace or per-handshake deadline renewal exists.
    /// # Errors
    /// Refuses an unrepresentable original schedule offset.
    pub fn deadline(&self) -> Result<Instant> {
        self.state.deadline()
    }
    /// Observe qualified clock health against the original, never-rebased mapping.
    /// # Errors
    /// Refuses a detected regression or original native-budget failure.
    pub fn observe_clock(&self, sample: &QualifiedClockSample) -> Result<()> {
        self.state.lease.check()?;
        self.state.lease.schedule.observe_clock(sample)
    }
    /// Same-host fixture observation; never a UTC qualification.
    /// # Errors
    /// Retains sticky clock/resource refusals.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&self) -> Result<()> {
        self.state.lease.check()?;
        self.state.lease.schedule.observe_functional_clock()
    }
    /// Verify A's exact roster within the window before any client enrollment.
    /// # Errors
    /// Refuses another role, repeated/late roster admission or active attempts.
    pub fn roster(&mut self, hashes: [Digest; 32]) -> Result<()> {
        self.state.check()?;
        if self.state.seal.resources.role() != Role::A || self.state.roster.is_some() {
            return Err(Error::Unavailable("setup roster role/reuse"));
        }
        let roster = Rc::new(Roster::verify(hashes, &self.state.seal.config)?);
        self.state.check()?;
        Rc::get_mut(&mut self.state)
            .ok_or(Error::Unavailable("roster after active setup"))?
            .roster = Some(roster);
        Ok(())
    }
    /// Claim the configured outgoing endpoint before its sole TCP attempt.
    /// # Errors
    /// Refuses another topology/profile, an attempted endpoint or shared capacity.
    pub fn connect(&self, peer: Role, profile: ClientProfile) -> Result<PendingConnection> {
        self.state.check()?;
        let role = self.state.seal.resources.role();
        if !matches!(
            (role, peer),
            (Role::A, Role::B) | (Role::B, Role::P0 | Role::P1 | Role::P2)
        ) || profile.endpoint() != self.config().endpoints()[peer as usize]
        {
            return Err(Error::Unavailable("setup outgoing topology/profile"));
        }
        self.state.claim_hop(peer)?;
        let permit = self.state.pending()?;
        let socket = self.state.seal.resources.socket()?;
        let connecting = Connecting::bounded(profile, self.deadline()?, socket)?;
        self.state.check()?;
        Ok(PendingConnection {
            stage: Some(Stage::Connecting(connecting)),
            target: Target::Hop(peer),
            _permit: permit,
            window: Rc::clone(&self.state),
        })
    }
    /// Reserve an incoming configured hop attempt. TLS alone does not authenticate
    /// its remote role; the new round must verify its normal signed controls.
    /// # Errors
    /// Refuses a foreign listener/root, used endpoint or shared pending capacity.
    pub fn accept_hop(&self, listener: Rc<Listener>) -> Result<PendingConnection> {
        self.state.check()?;
        let role = self.state.seal.resources.role();
        let peer = match role {
            Role::B => Role::A,
            Role::P0 | Role::P1 | Role::P2 => Role::B,
            Role::A => return Err(Error::Unavailable("A has no incoming hop")),
        };
        self.listener(&listener)?;
        self.state.claim_hop(peer)?;
        let permit = self.state.pending()?;
        Ok(PendingConnection {
            stage: Some(Stage::Accepting(listener)),
            target: Target::Hop(peer),
            _permit: permit,
            window: Rc::clone(&self.state),
        })
    }
    /// Wait for one anonymous A connection under the role-wide two-setup cap.
    /// Only a verified Join claims a roster identity; IP is never identity evidence.
    /// # Errors
    /// Refuses wrong role/roster/listener, exhausted accepted-attempt budget or caps.
    pub fn accept_client(&self, listener: Rc<Listener>) -> Result<PendingConnection> {
        self.state.check()?;
        if self.state.seal.resources.role() != Role::A
            || self.state.roster.is_none()
            || u32::from(self.state.accepted_clients.get())
                >= self.state.allowed_clients.count_ones()
        {
            return Err(Error::Unavailable("setup client roster/attempt budget"));
        }
        self.listener(&listener)?;
        let permit = self.state.pending()?;
        Ok(PendingConnection {
            stage: Some(Stage::Accepting(listener)),
            target: Target::Client,
            _permit: permit,
            window: Rc::clone(&self.state),
        })
    }
    fn listener(&self, listener: &Listener) -> Result<()> {
        if listener.endpoint()
            != self.config().endpoints()[self.state.seal.resources.role() as usize]
            || listener
                .resources()
                .is_none_or(|root| !root.same(&self.state.seal.resources))
        {
            return Err(Error::Unavailable("setup configured listener/root"));
        }
        Ok(())
    }
    /// Retain one completed candidate in this bounded window's private pool.
    /// # Errors
    /// Refuses another window or duplicate endpoint; no candidate is rebound.
    pub fn retain(&mut self, candidate: ConnectionCandidate) -> Result<()> {
        self.state.check()?;
        if !Rc::ptr_eq(&candidate.seal, &self.state.seal) {
            return Err(Error::Unavailable("setup foreign candidate"));
        }
        let prepared = self
            .prepared
            .as_mut()
            .ok_or(Error::Unavailable("setup pool already taken"))?;
        match candidate.body {
            CandidateBody::Hop(peer, transport) => {
                if prepared.hops[peer as usize].is_some() {
                    return Err(Error::Unavailable("setup duplicate hop candidate"));
                }
                prepared.hops[peer as usize] = Some(transport);
            }
            CandidateBody::Client(session) => {
                if prepared.sessions.len() >= 32 {
                    return Err(Error::Unavailable("setup client candidate cap"));
                }
                prepared.sessions.push(session);
            }
        }
        Ok(())
    }
    /// Finish before the original deadline with no pending TCP/TLS/Join. The
    /// resulting pool deliberately retains NO original native timer/round lease.
    /// # Errors
    /// Refuses expiry, failed admission or an outstanding attempt.
    pub fn finish(mut self) -> Result<PreparedConnections> {
        self.state.check()?;
        if self.state.pending.get() != 0 {
            return Err(Error::Unavailable("setup attempts still pending"));
        }
        let prepared = self
            .prepared
            .take()
            .ok_or(Error::Unavailable("setup pool already taken"))?;
        self.state.seal.complete.set(true);
        Ok(prepared)
    }
}

#[derive(Clone, Copy)]
enum Target {
    Hop(Role),
    Client,
}
#[allow(clippy::large_enum_variant)]
enum Stage {
    Accepting(Rc<Listener>),
    Connecting(Connecting),
    Tls(Setup),
    Join(Enrolling),
}

/// One consuming incremental TCP/TLS/Join attempt retaining original budget and
/// deadline. Dropping/error closes its socket; it cannot grant another attempt.
pub struct PendingConnection {
    stage: Option<Stage>,
    target: Target,
    _permit: PendingPermit,
    window: Rc<WindowState>,
}
/// One bounded setup transition; a candidate is not yet installed in a role.
pub enum SetupProgress {
    /// Same exact socket, offsets, budget, window and pending permit.
    Pending(PendingConnection),
    /// A completed candidate, with no original timer ownership.
    Complete(ConnectionCandidate),
}
impl PendingConnection {
    /// Observe an actual qualified clock sample and advance one bounded operation.
    /// # Errors
    /// Refuses original clock/window/budget, transport or Join failure.
    pub fn poll(self, sample: &QualifiedClockSample) -> Result<SetupProgress> {
        self.window.lease.schedule.observe_clock(sample)?;
        self.advance()
    }
    /// Explicit unqualified functional observation, retaining original deadlines.
    /// # Errors
    /// Preserves every resource, transcript and token refusal.
    #[cfg(feature = "functional-lab")]
    pub fn poll_functional(self) -> Result<SetupProgress> {
        self.window.lease.schedule.observe_functional_clock()?;
        self.advance()
    }
    fn advance(mut self) -> Result<SetupProgress> {
        self.window.check()?;
        let mut complete = None;
        let next = match self.stage.take().expect("owned setup stage") {
            Stage::Accepting(listener) => {
                if matches!(self.target, Target::Client)
                    && u32::from(self.window.accepted_clients.get())
                        >= self.window.allowed_clients.count_ones()
                {
                    return Err(Error::Unavailable("setup anonymous attempt budget"));
                }
                let result = listener.accept_bounded(
                    self.window.deadline()?,
                    self.window.seal.resources.socket()?,
                );
                if matches!(self.target, Target::Client) && !matches!(&result, Ok(None)) {
                    self.window
                        .accepted_clients
                        .set(self.window.accepted_clients.get() + 1);
                }
                Some(result?.map_or_else(|| Stage::Accepting(listener), Stage::Tls))
            }
            Stage::Connecting(connecting) => Some(match connecting.poll()? {
                ConnectStep::Pending(pending) => Stage::Connecting(pending),
                ConnectStep::Handshaking(setup) => Stage::Tls(setup),
            }),
            Stage::Tls(setup) => match setup.poll()? {
                SetupStep::Pending(pending) => Some(Stage::Tls(pending)),
                SetupStep::Established(transport) => match self.target {
                    Target::Hop(peer) => {
                        complete = Some(CandidateBody::Hop(peer, transport));
                        None
                    }
                    Target::Client => Some(Stage::Join(Enrolling::new(
                        transport,
                        self.window.deadline()?,
                    )?)),
                },
            },
            Stage::Join(enrolling) => match enrolling.poll(
                &self.window.seal.config,
                self.window
                    .roster
                    .as_ref()
                    .ok_or(Error::Unavailable("setup roster absent"))?,
            )? {
                Enrollment::Pending(pending) => Some(Stage::Join(pending)),
                Enrollment::Admitted(session) => {
                    let bit = 1 << session.slot();
                    if self.window.allowed_clients & bit == 0
                        || self.window.joined_clients.get() & bit != 0
                    {
                        self.window.seal.failed.set(true);
                        return Err(Error::Invalid("setup duplicate/nonrepairable roster slot"));
                    }
                    self.window
                        .joined_clients
                        .set(self.window.joined_clients.get() | bit);
                    complete = Some(CandidateBody::Client(session));
                    None
                }
            },
        };
        self.stage = next;
        // Required AFTER all TLS/Join/token work; no backdated acceptance.
        self.window.check()?;
        if let Some(body) = complete {
            return Ok(SetupProgress::Complete(ConnectionCandidate {
                body,
                seal: Rc::clone(&self.window.seal),
            }));
        }
        Ok(SetupProgress::Pending(self))
    }
}
enum CandidateBody {
    Hop(Role, Transport),
    Client(AdmittedSession),
}
/// Non-forgeable completed transport/Join and exact target provenance. Not a
/// signed-role assertion, completed pool or permission to mutate active streams.
pub struct ConnectionCandidate {
    body: CandidateBody,
    seal: Rc<Seal>,
}

/// Bounded finished setup result. Existing actors cannot consume these sockets;
/// role-owner promotion must check its eligibility and immutable configuration.
pub struct PreparedConnections {
    hops: [Option<Transport>; 5],
    sessions: Vec<AdmittedSession>,
    seal: Rc<Seal>,
}
impl PreparedConnections {
    pub(crate) fn repair_target(
        &self,
        config: &SignedConfig,
        resources: &RoleResources,
    ) -> Result<()> {
        self.check(resources)?;
        if self.purpose() != SetupPurpose::Maintenance || self.config().id() != config.id() {
            return Err(Error::Unavailable("maintenance pool context/purpose"));
        }
        Ok(())
    }
    pub(crate) const fn has_clients(&self) -> bool {
        !self.sessions.is_empty()
    }
    pub(crate) fn check_links(&self, links: &[(Role, &Transport)]) -> Result<()> {
        for (peer, transport) in links {
            if self.hops[*peer as usize].is_some()
                && transport.receive_progress() != crate::tls::ReceiveProgress::Failed
            {
                return Err(Error::Unavailable(
                    "maintenance cannot replace a healthy link",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn check_sessions(&self, sessions: &Sessions) -> Result<()> {
        sessions.check_replacements(&self.sessions)
    }
    pub(crate) fn repairs(self, round: u64) -> Result<RepairParts> {
        if round < self.eligible_from()
            || !self.config().contains_round(round)
            || self.purpose() != SetupPurpose::Maintenance
        {
            return Err(Error::Unavailable(
                "maintenance round not yet/wholly eligible",
            ));
        }
        Ok(RepairParts {
            hops: self.hops,
            sessions: self.sessions,
        })
    }
    /// Earliest wholly configured round; a role's restart floor may be stricter.
    #[must_use]
    pub fn eligible_from(&self) -> u64 {
        self.seal.eligible
    }
    /// Exact fixed lifecycle purpose, not a caller-supplied flag.
    #[must_use]
    pub fn purpose(&self) -> SetupPurpose {
        self.seal.purpose
    }
    /// Exact admitted immutable target configuration.
    #[must_use]
    pub fn config(&self) -> &SignedConfig {
        &self.seal.config
    }
    pub(crate) fn check(&self, resources: &RoleResources) -> Result<()> {
        if !self.seal.complete.get()
            || self.seal.failed.get()
            || !self.seal.resources.same(resources)
        {
            return Err(Error::Unavailable("setup unfinished/failed/foreign pool"));
        }
        Ok(())
    }
    pub(crate) fn source(
        mut self,
        resources: &RoleResources,
    ) -> Result<(Rc<SignedConfig>, Sessions, Transport)> {
        self.check(resources)?;
        if resources.role() != Role::A
            || self.sessions.len() != 32
            || self.purpose() != SetupPurpose::NextEpoch
        {
            return Err(Error::Unavailable("next A complete setup pool"));
        }
        let mut sessions = Sessions::new(&self.seal.config);
        for session in self.sessions {
            sessions.insert(session)?;
        }
        let b = self.hops[Role::B as usize]
            .take()
            .ok_or(Error::Unavailable("next A B connection absent"))?;
        Ok((Rc::clone(&self.seal.config), sessions, b))
    }
    pub(crate) fn exit(
        mut self,
        resources: &RoleResources,
    ) -> Result<(Rc<SignedConfig>, Transport, [Transport; 3])> {
        self.check(resources)?;
        if resources.role() != Role::B || self.purpose() != SetupPurpose::NextEpoch {
            return Err(Error::Unavailable("next B setup pool"));
        }
        let a = self.hops[Role::A as usize]
            .take()
            .ok_or(Error::Unavailable("next B A connection absent"))?;
        let mut take = |i: usize| {
            self.hops[i]
                .take()
                .ok_or(Error::Unavailable("next B producer connection absent"))
        };
        let producers = [take(2)?, take(3)?, take(4)?];
        Ok((Rc::clone(&self.seal.config), a, producers))
    }
    pub(crate) fn producer(
        mut self,
        resources: &RoleResources,
    ) -> Result<(Rc<SignedConfig>, Transport)> {
        self.check(resources)?;
        if !matches!(resources.role(), Role::P0 | Role::P1 | Role::P2)
            || self.purpose() != SetupPurpose::NextEpoch
        {
            return Err(Error::Unavailable("next producer setup pool"));
        }
        let b = self.hops[Role::B as usize]
            .take()
            .ok_or(Error::Unavailable("next producer B connection absent"))?;
        Ok((Rc::clone(&self.seal.config), b))
    }
}

pub(crate) struct RepairParts {
    pub(crate) hops: [Option<Transport>; 5],
    pub(crate) sessions: Vec<AdmittedSession>,
}
