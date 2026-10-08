//! One four-round private fixture: EOF abort, bounded silence, repair, old/new overlap.
use super::{
    Result, files,
    owners::LabOwner,
    roles::{Public, TICK, round_schedule},
};
use silk_f04_relay::{
    control::Role,
    exit_owner::ExitOwner,
    frame::Payload,
    lifecycle::{
        FunctionalOwnerSnapshot, PendingConnection, PreparedConnections, SetupProgress, SetupWindow,
    },
    negotiation::SelectedCut,
    producer_owner::ProducerOwner,
    resources::RoleResources,
    schedule::Schedule,
    source_owner::SourceOwner,
    tls::{ClientProfile, Listener},
};
use std::{collections::VecDeque, path::Path, rc::Rc, thread, time::Instant};

#[allow(clippy::large_enum_variant)] // Exactly one actual process owner, never parallel relay roles.
pub enum Relay {
    Source(SourceOwner<files::Pins>),
    Exit(ExitOwner<files::Pins>),
    Producer(ProducerOwner),
}
impl LabOwner for Relay {
    fn start(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        match self {
            Self::Source(o) => o.start(schedule, cut),
            Self::Exit(o) => o.start(schedule, cut),
            Self::Producer(o) => o.start(schedule, cut),
        }
    }
    fn tick(&mut self) -> Result<Instant> {
        match self {
            Self::Source(o) => o.tick(),
            Self::Exit(o) => o.tick(),
            Self::Producer(o) => o.tick(),
        }
    }
    fn closed(&mut self) -> Option<(u64, bool, bool)> {
        match self {
            Self::Source(o) => o.closed(),
            Self::Exit(o) => o.closed(),
            Self::Producer(o) => o.closed(),
        }
    }
    fn released(&mut self) -> Option<(u64, [Payload; 32])> {
        match self {
            Self::Source(o) => o.released(),
            Self::Exit(o) => o.released(),
            Self::Producer(o) => o.released(),
        }
    }
}
impl Relay {
    fn resources(&self) -> RoleResources {
        match self {
            Self::Source(o) => o.resources(),
            Self::Exit(o) => o.resources(),
            Self::Producer(o) => o.resources(),
        }
    }
    fn snapshot(&self) -> Result<FunctionalOwnerSnapshot> {
        Ok(match self {
            Self::Source(o) => o.functional_snapshot()?,
            Self::Exit(o) => o.functional_snapshot()?,
            Self::Producer(o) => o.functional_snapshot(),
        })
    }
    fn epoch(&self, round: u64, next: &Public) -> Result<SetupWindow> {
        let roots = next.config_roots()?;
        Ok(match self {
            Self::Source(o) => o.next_epoch_window(round, next.config.bytes(), roots)?,
            Self::Exit(o) => o.next_epoch_window(round, next.config.bytes(), roots)?,
            Self::Producer(o) => o.next_epoch_window(round, next.config.bytes(), roots)?,
        })
    }
    fn install(&mut self, prepared: PreparedConnections, next: &Public, role: Role) -> Result<()> {
        let identity = next.identity(role)?;
        match self {
            Self::Source(o) => o.install_next(prepared, identity, Rc::new(next.hpke()?))?,
            Self::Exit(o) => o.install_next(prepared, identity, Rc::new(next.hpke()?))?,
            Self::Producer(o) => o.install_next(prepared, identity)?,
        }
        Ok(())
    }
}

enum Attempt {
    Hop(Rc<Listener>),
    Client(Rc<Listener>),
    Connect(Role, ClientProfile),
}
struct Work {
    // Pending sockets drop before the setup window's original native lease.
    pending: Vec<PendingConnection>,
    tasks: VecDeque<Attempt>,
    window: SetupWindow,
    completed: usize,
}
impl Work {
    fn repair(window: SetupWindow, listener: Rc<Listener>, public: &Public) -> Result<Self> {
        let mut work = Self {
            pending: Vec::with_capacity(2),
            tasks: VecDeque::from([Attempt::Client(listener)]),
            window,
            completed: 0,
        };
        work.window.roster(public.roster_hashes()?)?;
        Ok(work)
    }
    fn epoch(
        mut window: SetupWindow,
        listener: Rc<Listener>,
        public: &Public,
        role: Role,
    ) -> Result<Self> {
        let mut tasks = VecDeque::with_capacity(33);
        if role == Role::A {
            window.roster(public.roster_hashes()?)?;
            tasks.push_back(Attempt::Connect(Role::B, public.client_profile(Role::B)?));
            for _ in 0..32 {
                tasks.push_back(Attempt::Client(Rc::clone(&listener)));
            }
        } else {
            tasks.push_back(Attempt::Hop(listener));
            if role == Role::B {
                for peer in [Role::P0, Role::P1, Role::P2] {
                    tasks.push_back(Attempt::Connect(peer, public.client_profile(peer)?));
                }
            }
        }
        Ok(Self {
            pending: Vec::with_capacity(2),
            tasks,
            window,
            completed: 0,
        })
    }
    fn poll(&mut self) -> Result<bool> {
        self.window.observe_functional_clock()?;
        while self.pending.len() < 2 {
            let Some(attempt) = self.tasks.pop_front() else {
                break;
            };
            self.pending.push(match attempt {
                Attempt::Hop(listener) => self.window.accept_hop(listener)?,
                Attempt::Client(listener) => self.window.accept_client(listener)?,
                Attempt::Connect(role, profile) => self.window.connect(role, profile)?,
            });
        }
        let mut retained = Vec::with_capacity(2);
        for pending in self.pending.drain(..) {
            match pending.poll_functional()? {
                SetupProgress::Pending(pending) => retained.push(pending),
                SetupProgress::Complete(candidate) => {
                    self.window.retain(candidate)?;
                    self.completed += 1;
                }
            }
        }
        self.pending = retained;
        Ok(self.pending.is_empty() && self.tasks.is_empty())
    }
    fn finish(self, expected: usize, eligible: u64) -> Result<PreparedConnections> {
        if self.completed != expected {
            return Err("lifecycle incomplete connection pool".into());
        }
        let prepared = self.window.finish()?;
        if prepared.eligible_from() != eligible {
            return Err("lifecycle wrong candidate eligibility".into());
        }
        Ok(prepared)
    }
}

fn check_overlap(owner: &Relay, initial: &FunctionalOwnerSnapshot, first: u64) -> Result<()> {
    let now = owner.snapshot()?;
    let old = now
        .live
        .iter()
        .flatten()
        .find(|r| r.round == first + 2)
        .ok_or("old-final not live at new-first")?;
    let new = now
        .live
        .iter()
        .flatten()
        .find(|r| r.round == first + 3)
        .ok_or("new-first not admitted")?;
    if now.floor != initial.floor
        || now.journal != initial.journal
        || now.highest != Some(first + 3)
        || old.config == new.config
        || old
            .hops
            .iter()
            .zip(new.hops)
            .any(|(a, b)| *a != 0 && (*a == b || b == 0))
    {
        return Err("lifecycle ownership continuity/connection isolation".into());
    }
    println!(
        "actual_old_new_overlap=true distinct_configurations=true distinct_actor_hops=true unchanged_journal_lock=true unchanged_cold_floor=true global_highest={}",
        first + 3
    );
    Ok(())
}

struct Receipts {
    closed: u64,
    delivered: u64,
}
impl Receipts {
    fn poll(&mut self, owner: &mut Relay, first: u64, role: &str) -> Result<()> {
        if let Some((round, payloads)) = owner.released() {
            if round != first + 1 + self.delivered {
                return Err("lifecycle out-of-order producer delivery".into());
            }
            let mut real = payloads.iter().filter_map(Payload::real_bytes);
            if round == first + 3 {
                let payment = real.next().ok_or("new-epoch actual payment absent")?;
                files::write_new(
                    &Path::new("/work/store").join(format!("{role}-payment-2790")),
                    payment,
                )?;
            }
            if real.next().is_some() {
                return Err("lifecycle unexpected real payload/retry".into());
            }
            self.delivered += 1;
            println!(
                "role={role} round={round} lifecycle_batch_opened=true real_payloads={}",
                u8::from(round == first + 3)
            );
        }
        if let Some((round, complete, failed)) = owner.closed() {
            let expected_abort = round == first;
            if round != first + self.closed
                || complete == expected_abort
                || failed != expected_abort
            {
                return Err("lifecycle unexpected round outcome".into());
            }
            self.closed += 1;
            println!(
                "role={role} round={round} owner_cleanup_complete=true expected_abort={expected_abort}"
            );
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)] // One retained owner and four fixed actual round transitions.
pub fn drive(
    public: &Public,
    first: u64,
    role: Role,
    old_listener: Rc<Listener>,
    mut owner: Relay,
) -> Result<()> {
    if !(first + 3).is_multiple_of(2880) {
        return Err("fixture must start three rounds before epoch".into());
    }
    let name = super::setup::ROLES[role as usize];
    let next = Public::load_next(first + 3)?;
    let next_listener = Rc::new(next.lifecycle_listener(role, &owner.resources())?);
    let initial = owner.snapshot()?;
    let schedule = round_schedule(public, first)?;
    let repair_claim_at = schedule.at(19_000_000_000)?;
    let repair_start = schedule.at(24_000_000_000)?;
    let epoch_start = schedule.at(30_000_000_000)?;
    let mut admit_at = repair_claim_at;
    owner.start(schedule, public.owned_cut(first)?)?;
    let mut admitted = 1;
    let mut repair_window = None;
    let mut repair_work = None;
    let mut repaired = role != Role::A;
    let mut epoch_work = None;
    let mut installed = false;
    let mut receipt = Receipts {
        closed: 0,
        delivered: 0,
    };
    loop {
        let mut wake = owner.tick()?;
        receipt.poll(&mut owner, first, name)?;
        let now = Instant::now();
        if role == Role::A
            && !repaired
            && repair_window.is_none()
            && repair_work.is_none()
            && now >= repair_claim_at
        {
            let Relay::Source(source) = &owner else {
                return Err("wrong source owner".into());
            };
            repair_window = Some(source.maintenance_window(first)?);
            if source.maintenance_window(first).is_ok() {
                return Err("maintenance claim reused".into());
            }
        }
        if now >= repair_start
            && let Some(window) = repair_window.take()
        {
            repair_work = Some(Work::repair(window, Rc::clone(&old_listener), public)?);
        }
        if let Some(work) = &mut repair_work
            && work.poll()?
        {
            let prepared = repair_work
                .take()
                .ok_or("repair work absent")?
                .finish(1, first + 2)?;
            let Relay::Source(source) = &mut owner else {
                return Err("wrong repair owner".into());
            };
            source.stage_repairs(prepared)?;
            repaired = true;
            println!(
                "role=a actual_repair_join=true eligible_from={} original_maintenance_window=true repeated_window_refused=true",
                first + 2
            );
        }
        if now >= epoch_start && !installed && epoch_work.is_none() {
            let window = owner.epoch(first + 1, &next)?;
            if owner.epoch(first + 1, &next).is_ok() {
                return Err("epoch claim reused".into());
            }
            epoch_work = Some(Work::epoch(window, Rc::clone(&next_listener), &next, role)?);
        }
        if let Some(work) = &mut epoch_work
            && work.poll()?
        {
            let count = match role {
                Role::A => 33,
                Role::B => 4,
                _ => 1,
            };
            let prepared = epoch_work
                .take()
                .ok_or("epoch work absent")?
                .finish(count, first + 3)?;
            owner.install(prepared, &next, role)?;
            installed = true;
            println!(
                "role={name} actual_epoch_pool_installed=true original_setup_window=true repeated_window_refused=true"
            );
        }
        if admitted < 4 && now >= admit_at {
            let round = first + admitted;
            let selected = if admitted == 3 { &next } else { public };
            let schedule = selected.owner_schedule(round)?;
            admit_at = schedule.at(19_000_000_000)?;
            owner.start(schedule, selected.owned_cut(round)?)?;
            admitted += 1;
            if admitted == 4 {
                check_overlap(&owner, &initial, first)?;
            }
        }
        if receipt.closed == 4 {
            break;
        }
        if admitted < 4 {
            wake = wake.min(admit_at);
        }
        if !repaired {
            wake = wake.min(if now < repair_claim_at {
                repair_claim_at
            } else if now < repair_start {
                repair_start
            } else {
                now + TICK
            });
        }
        if !installed {
            wake = wake.min(if now < epoch_start {
                epoch_start
            } else {
                now + TICK
            });
        }
        thread::sleep(wake.saturating_duration_since(Instant::now()));
    }
    let final_state = owner.snapshot()?;
    if !repaired
        || !installed
        || final_state.live.iter().any(Option::is_some)
        || final_state.floor != initial.floor
        || final_state.journal != initial.journal
        || (name.starts_with('p') && receipt.delivered != 3)
    {
        return Err("lifecycle final ownership/delivery incomplete".into());
    }
    println!(
        "role={name} four_round_lifecycle_success=true functional_only=true qualified_utc=false independent_custody=false"
    );
    drop(old_listener);
    Ok(())
}
