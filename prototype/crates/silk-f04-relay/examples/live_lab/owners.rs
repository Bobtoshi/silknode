//! Three consecutive actual rounds on the same epoch links and durable journals.
//! No epoch-rotation, qualified-clock, independent-custody or privacy claim.
use super::{
    Result, files,
    roles::{Public, round_schedule},
};
use silk_f04_relay::{
    exit_owner::ExitOwner, frame::Payload, negotiation::SelectedCut, producer_owner::ProducerOwner,
    schedule::Schedule, source_owner::SourceOwner,
};
use std::{path::Path, thread, time::Instant};

pub trait LabOwner {
    fn start(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()>;
    fn tick(&mut self) -> Result<Instant>;
    fn closed(&mut self) -> Option<(u64, bool, bool)>;
    fn released(&mut self) -> Option<(u64, [Payload; 32])> {
        None
    }
}
impl LabOwner for SourceOwner<files::Pins> {
    fn start(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        Ok(self.admit(schedule, cut)?)
    }
    fn tick(&mut self) -> Result<Instant> {
        Ok(self.poll_functional()?)
    }
    fn closed(&mut self) -> Option<(u64, bool, bool)> {
        self.take_closed()
    }
}
impl LabOwner for ExitOwner<files::Pins> {
    fn start(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        Ok(self.admit(schedule, cut)?)
    }
    fn tick(&mut self) -> Result<Instant> {
        Ok(self.poll_functional()?)
    }
    fn closed(&mut self) -> Option<(u64, bool, bool)> {
        self.take_closed()
    }
}
impl LabOwner for ProducerOwner {
    fn start(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        Ok(self.admit(schedule, cut)?)
    }
    fn tick(&mut self) -> Result<Instant> {
        Ok(self.poll_functional()?)
    }
    fn closed(&mut self) -> Option<(u64, bool, bool)> {
        self.take_closed()
    }
    fn released(&mut self) -> Option<(u64, [Payload; 32])> {
        self.take_released()
    }
}

pub fn drive(
    public: &Public,
    first: u64,
    role: &str,
    failed_first: bool,
    mut owner: impl LabOwner,
) -> Result<()> {
    let schedule = round_schedule(public, first)?;
    let mut admit_at = schedule.at(19_000_000_000)?;
    owner.start(schedule, public.owned_cut(first)?)?;
    let mut admitted = 1;
    let mut closed = 0;
    let mut delivered = 0;
    loop {
        let mut wake = owner.tick()?;
        if let Some((round, payloads)) = owner.released() {
            if round != first + delivered + u64::from(failed_first) {
                return Err("out-of-order owner delivery".into());
            }
            let mut real = payloads.iter().filter_map(Payload::real_bytes);
            if round == first && !failed_first {
                let payment = real.next().ok_or("owner no actual delivered payment")?;
                if real.next().is_some() {
                    return Err("owner excess real payload".into());
                }
                files::write_new(
                    &Path::new("/work/store").join(format!("{role}-payment-2790")),
                    payment,
                )?;
            } else if real.next().is_some() {
                return Err("successor must be cover only, never a wallet retry".into());
            }
            delivered += 1;
            println!(
                "role={role} round={round} owner_batch_opened=true real_payloads={} same_connections=true",
                u8::from(round == first)
            );
        }
        if let Some((round, complete, failed)) = owner.closed() {
            let expected_failure = failed_first && round == first;
            if round != first + closed || complete == expected_failure || failed != expected_failure
            {
                return Err("owner round did not close successfully".into());
            }
            closed += 1;
            println!(
                "role={role} round={round} owner_cleanup_complete=true expected_abort={expected_failure} same_journal=true"
            );
        }
        if closed == 3 {
            break;
        }
        if admitted < 3 {
            if Instant::now() >= admit_at {
                let round = first + admitted;
                let schedule = public.owner_schedule(round)?;
                admit_at = schedule.at(19_000_000_000)?;
                owner.start(schedule, public.owned_cut(round)?)?;
                admitted += 1;
            }
            if admitted < 3 {
                wake = wake.min(admit_at);
            }
        }
        thread::sleep(wake.saturating_duration_since(Instant::now()));
    }
    if role.starts_with('p') && delivered != 3 - u64::from(failed_first) {
        return Err("owner missing complete producer batches".into());
    }
    println!(
        "role={role} three_round_owner_success=true expected_first_abort={failed_first} functional_only=true epoch_lifecycle=false"
    );
    Ok(())
}
