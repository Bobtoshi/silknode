//! 32 combined fixture clients; never evidence of independent custody/honesty.
use super::{
    Result,
    roles::{Public, TICK, round_schedule},
};
use silk_f04_relay::{
    control::Role,
    frame::{Payload, RoundContext, client_cell},
    runtime::RoundGuard,
    schedule::Schedule,
    tls::{ClientProfile, ConnectStep, Connecting, RecordSize, Setup, SetupStep, Transport},
};
use silk_sapling_f04::codec::Envelope;
use std::{
    rc::Rc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

enum Pending {
    Connect(Connecting),
    Tls(Setup),
    Join(Transport),
}
impl Pending {
    fn start(profile: ClientProfile, end: Instant) -> Result<Self> {
        Ok(Self::Connect(Connecting::with_profile(profile, end)?))
    }
    fn poll(
        self,
        public: &Public,
        token: &[u8],
        end: Instant,
    ) -> Result<(Option<Self>, Option<Transport>)> {
        Ok(match self {
            Self::Connect(p) => (
                Some(match p.poll()? {
                    ConnectStep::Pending(p) => Self::Connect(p),
                    ConnectStep::Handshaking(p) => Self::Tls(p),
                }),
                None,
            ),
            Self::Tls(p) => match p.poll()? {
                SetupStep::Pending(p) => (Some(Self::Tls(p)), None),
                SetupStep::Established(mut transport) => {
                    let mut join = Zeroizing::new([0; 128]);
                    join[..8].copy_from_slice(b"SNJOIN03");
                    join[8..40].copy_from_slice(&public.config.domain());
                    join[40..44].copy_from_slice(&public.config.cohort().to_le_bytes());
                    join[44..48].copy_from_slice(&public.config.epoch().to_le_bytes());
                    join[48..80].copy_from_slice(token);
                    transport.queue(RecordSize::Join, join.as_ref(), end)?;
                    (Some(Self::Join(transport)), None)
                }
            },
            Self::Join(mut transport) => {
                if transport.write_step()? {
                    (None, Some(transport))
                } else {
                    (Some(Self::Join(transport)), None)
                }
            }
        })
    }
}

struct NextClients<'a> {
    pending: Option<Pending>,
    links: Vec<Transport>,
    public: &'a Public,
    profile: ClientProfile,
    tokens: Zeroizing<[u8; 1024]>,
    start: Instant,
    end: Instant,
}
impl<'a> NextClients<'a> {
    fn new(public: &'a Public, start: Instant) -> Result<Self> {
        Ok(Self {
            pending: None,
            links: Vec::with_capacity(32),
            public,
            profile: public.client_profile(Role::A)?,
            tokens: public.tokens()?,
            start,
            end: start + Duration::from_secs(30),
        })
    }
    fn poll(&mut self) -> Result<()> {
        if Instant::now() < self.start || self.links.len() == 32 {
            return Ok(());
        }
        if Instant::now() >= self.end {
            return Err("client epoch setup missed original deadline".into());
        }
        let pending = match self.pending.take() {
            Some(p) => p,
            None => Pending::start(self.profile.clone(), self.end)?,
        };
        let at = self.links.len() * 32;
        let (pending, complete) = pending.poll(self.public, &self.tokens[at..at + 32], self.end)?;
        self.pending = pending;
        if let Some(transport) = complete {
            self.links.push(transport);
        }
        Ok(())
    }
    fn nap(&self, until: Instant) {
        let interval = if Instant::now() >= self.start && self.links.len() < 32 {
            TICK
        } else {
            Duration::from_millis(10)
        };
        thread::sleep(
            until
                .saturating_duration_since(Instant::now())
                .min(interval),
        );
    }
    fn wait(&mut self, until: Instant) -> Result<()> {
        while Instant::now() < until {
            self.poll()?;
            self.nap(until);
        }
        Ok(())
    }
}

fn round(
    public: &Public,
    schedule: &Schedule,
    envelope: &Envelope,
    offset: usize,
    links: &mut [Option<Transport>],
    setup: &mut NextClients<'_>,
) -> Result<()> {
    let mut frames = Vec::with_capacity(32);
    let mut manifest_id = None;
    let cutoff = schedule.at(1_000_000_000)?;
    setup.wait(schedule.at(-9_000_000_000)?)?;
    for (i, link) in links.iter_mut().enumerate() {
        let Some(transport) = link else {
            frames.push(None);
            continue;
        };
        transport.expect(RecordSize::Manifest, cutoff)?;
        let bytes = loop {
            setup.poll()?;
            if let Some(bytes) = transport.read_step()? {
                break bytes;
            }
            setup.nap(cutoff);
        };
        schedule.observe_functional_clock()?;
        let manifest =
            public
                .owned_cut(schedule.round())?
                .admit_signed(&bytes, &public.config, schedule)?;
        if manifest_id.is_some_and(|id| id != manifest.id()) {
            return Err("lifecycle conflicting client manifests".into());
        }
        manifest_id = Some(manifest.id());
        if offset == 0 && i == 31 {
            // Exact final roster slot, AFTER its actual manifest but BEFORE cell.
            // Dropping this genuine stream is the only induced availability fault.
            *link = None;
            frames.push(None);
            continue;
        }
        let context = RoundContext::new(&public.config, &manifest)?;
        let payload = if offset == 3 && i == 0 {
            Payload::real(envelope, &context)?
        } else {
            Payload::cover()
        };
        frames.push(Some(client_cell(&context, &payload)?));
        schedule.completed_before(1_000_000_000)?;
    }
    for (i, (link, frame)) in links.iter_mut().zip(frames.iter()).enumerate() {
        let (Some(transport), Some(frame)) = (link, frame) else {
            continue;
        };
        let start = 1_000_000_000 + i64::try_from(i)? * 250_000_000;
        setup.wait(schedule.at(start)?)?;
        schedule.observe_functional_clock()?;
        schedule.in_window(start, start + 250_000_000)?;
        let end = schedule.at(start + 250_000_000)?;
        transport.queue(RecordSize::Cell, frame.bytes(), end)?;
        while !transport.write_step()? {
            setup.poll()?;
            setup.nap(end);
        }
        schedule.completed_before(start + 250_000_000)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One four-round client flow retains the two original native leases.
pub fn drive(
    public: &Public,
    first: u64,
    envelope: &Envelope,
    connections: Vec<Transport>,
) -> Result<()> {
    if !(first + 3).is_multiple_of(2880) {
        return Err("client fixture epoch mapping".into());
    }
    let next = Public::load_next(first + 3)?;
    let schedule = Rc::new(round_schedule(public, first)?);
    // Declaration order: all selected links/setup buffers drop before timer owners.
    let mut leases: [Option<(Rc<Schedule>, RoundGuard)>; 2] = [None, None];
    leases[0] = Some((Rc::clone(&schedule), RoundGuard::arm(&schedule)?));
    let mut links: Vec<_> = connections.into_iter().map(Some).collect();
    let mut repaired = None;
    let mut setup = NextClients::new(&next, schedule.at(30_000_000_000)?)?;
    for offset in 0..4 {
        let index = offset % 2;
        let schedule = Rc::clone(
            &leases[index]
                .as_ref()
                .ok_or("client native lease absent")?
                .0,
        );
        if offset == 2 {
            links[31] = Some(repaired.take().ok_or("actual repaired client absent")?);
            println!(
                "role=clients actual_repair_first_used={} not_used_in_preceding_round=true",
                schedule.round()
            );
        }
        if offset == 3 {
            if setup.links.len() != 32 {
                return Err("new epoch client pool incomplete".into());
            }
            links = std::mem::take(&mut setup.links)
                .into_iter()
                .map(Some)
                .collect();
            // Do not reopen setup when transferring the already completed pool.
            setup.start = schedule.at(30_000_000_000)?;
        }
        let selected = if offset == 3 { &next } else { public };
        round(
            selected, &schedule, envelope, offset, &mut links, &mut setup,
        )?;
        if offset < 3 {
            setup.wait(schedule.at(19_000_000_000)?)?;
            let selected = if offset == 2 { &next } else { public };
            let next_schedule = Rc::new(selected.owner_schedule(schedule.round() + 1)?);
            let guard = RoundGuard::arm(&next_schedule)?;
            leases[1 - index] = Some((next_schedule, guard));
        }
        setup.wait(schedule.at(22_000_000_000)?)?;
        if offset == 0 {
            // The original first native lease remains armed through +24..+28;
            // no replacement timer or per-attempt five-second extension exists.
            setup.wait(schedule.at(24_000_000_000)?)?;
            let end = schedule.at(28_000_000_000)?;
            let tokens = public.tokens()?;
            let mut pending = Pending::start(public.client_profile(Role::A)?, end)?;
            loop {
                let (remaining, complete) = pending.poll(public, &tokens[31 * 32..], end)?;
                if let Some(transport) = complete {
                    repaired = Some(transport);
                    break;
                }
                pending = remaining.ok_or("repair pending disappeared")?;
                thread::sleep(TICK);
            }
            println!(
                "role=clients original_maintenance_join_written=true eligible_from={}",
                first + 2
            );
        }
        if offset == 1 {
            while setup.links.len() != 32 {
                setup.poll()?;
                setup.nap(setup.end);
            }
            println!("role=clients actual_new_epoch_joins=32 original_setup_window=true");
        }
        if offset == 3 {
            // Retire the final connection/buffer owners BEFORE the last original
            // native lease is checked and disarmed, including this normal path.
            links.clear();
            setup.pending = None;
            setup.links.clear();
            repaired = None;
        }
        let (_, guard) = leases[index]
            .take()
            .ok_or("closed client native lease absent")?;
        guard.check()?;
        println!(
            "role=clients round={} client_frames_retired=true real_payloads={}",
            schedule.round(),
            u8::from(offset == 3)
        );
    }
    println!(
        "role=clients four_round_lifecycle_success=true functional_only=true qualified_utc=false honest_participants_unproven=true"
    );
    Ok(())
}
