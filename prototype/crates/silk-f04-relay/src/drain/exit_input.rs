//! Failed B ingress: bounded discarded cells/readiness/ACKs, never evidence.
use super::{
    Duration, Error, Instant, Rc, ReceiveProgress, RecordSize, Result, Schedule, Transport,
};

enum AState {
    Waiting,
    Reading(RecordSize),
    Done,
}
#[cfg(test)]
mod tests;

pub struct ExitInputDrain {
    schedule: Rc<Schedule>,
    connections: [u64; 4],
    cells: u8,
    a_state: AState,
    acks: [bool; 3],
    ack_reading: [bool; 3],
    acks_done: bool,
}
impl ExitInputDrain {
    pub(crate) const fn new(
        schedule: Rc<Schedule>,
        connections: [u64; 4],
        cells: u8,
        ready: bool,
        acks: [bool; 3],
    ) -> Self {
        Self {
            schedule,
            connections,
            cells,
            a_state: if ready { AState::Done } else { AState::Waiting },
            acks,
            ack_reading: [false; 3],
            acks_done: false,
        }
    }
    pub(crate) fn poll(
        &mut self,
        a: &mut Transport,
        producers: &mut [impl std::borrow::BorrowMut<Transport>; 3],
    ) -> Result<bool> {
        let mut producers = producers.each_mut().map(std::borrow::BorrowMut::borrow_mut);
        if [
            a.id(),
            producers[0].id(),
            producers[1].id(),
            producers[2].id(),
        ] != self.connections
        {
            return Err(Error::Unavailable("B discard connection replaced"));
        }
        self.schedule.clock_healthy()?;
        if !self.a_done() && self.poll_a(a).is_err() {
            let _ = a.quarantine();
            self.a_state = AState::Done;
        }
        if !self.acks_done {
            let cutoff = self.schedule.at(18_000_000_000)?;
            let cleanup_pass = Instant::now() >= cutoff;
            for (i, link) in producers.iter_mut().enumerate() {
                if self.poll_ack(link, i, cutoff).is_err() {
                    let _ = link.quarantine();
                    self.acks[i] = true; // Unavailable, not received/valid evidence.
                }
            }
            // Crossing the cutoff midway through a normal pass is not proof
            // that earlier links retired their original selected ACK reads.
            self.acks_done = cleanup_pass;
        }
        Ok(self.a_done() && self.acks_done)
    }
    fn poll_a(&mut self, link: &mut Transport) -> Result<()> {
        let cutoff = self.schedule.at(14_000_000_000)?;
        if self.a_done() {
            // A readiness already consumed: preserve any later lane-owned
            // partial read; do not inspect/reset it from this earlier cursor.
            return Ok(());
        }
        let progress = link.receive_progress();
        if progress == ReceiveProgress::Failed
            || (!matches!(self.a_state, AState::Reading(_))
                && matches!(progress, ReceiveProgress::Partial { .. }))
        {
            return Err(Error::Unavailable("B failed input already partial"));
        }
        if Instant::now() >= cutoff {
            if link.selected_read().is_some() {
                link.retire_expired_read()?;
            }
            if link.has_extra_bytes()? {
                return Err(Error::Unavailable("B late failed input"));
            }
            self.a_state = AState::Done;
            return Ok(());
        }
        if Instant::now() < self.schedule.at(9_000_000_000)? {
            return Ok(());
        }
        if !matches!(self.a_state, AState::Reading(_)) {
            // An untouched expired proposal selection cannot be renewed as data.
            if let Some((_, end)) = link.selected_read()
                && Instant::now() >= end
            {
                link.retire_expired_read()?;
            }
            let Some(size) = link.peek_record_size()? else {
                return Ok(());
            };
            let control = size == RecordSize::Control;
            let start = if control {
                10_000_000_000
            } else {
                9_000_000_000 + i64::from(self.cells) * 31_250_000
            };
            if Instant::now() < self.schedule.at(start)? {
                return Ok(());
            }
            if !(control || size == RecordSize::Cell && self.cells < 32) {
                return Err(Error::Invalid("B failed ingress class/count"));
            }
            if let Some((selected, end)) = link.selected_read() {
                if end != cutoff {
                    return Err(Error::Unavailable("B foreign discard deadline"));
                }
                if selected != size {
                    link.retire_empty(selected)?;
                }
            }
            if link.selected_read().is_none() {
                link.expect(size, cutoff)?;
            }
            self.a_state = AState::Reading(size);
        }
        if let Some(_bytes) = link.read_step()? {
            // Discard is not framing/HPKE/signature acceptance and exposes nothing.
            if matches!(self.a_state, AState::Reading(RecordSize::Control)) {
                self.a_state = AState::Done;
            } else {
                self.cells += 1;
                self.a_state = AState::Waiting;
            }
        }
        Ok(())
    }
    fn poll_ack(&mut self, link: &mut Transport, index: usize, cutoff: Instant) -> Result<()> {
        if link.receive_progress() == ReceiveProgress::Failed {
            return Ok(());
        }
        if Instant::now() >= cutoff {
            if link.selected_read().is_some() {
                link.retire_expired_read()?;
            }
            if link.has_extra_bytes()? {
                return Err(Error::Unavailable("B extra/late failed ACK"));
            }
            return Ok(());
        }
        if self.acks[index] || Instant::now() < self.schedule.at(16_000_000_000)? {
            return Ok(());
        }
        if !self.ack_reading[index] {
            if matches!(link.receive_progress(), ReceiveProgress::Partial { .. }) {
                return Err(Error::Unavailable("B original ACK already partial"));
            }
            if link.receive_progress() == ReceiveProgress::Idle {
                link.expect(RecordSize::Control, cutoff)?;
            }
            if link.selected_read() != Some((RecordSize::Control, cutoff)) {
                return Err(Error::Unavailable("B foreign ACK discard selection"));
            }
            self.ack_reading[index] = true;
        }
        if let Some(_bytes) = link.read_step()? {
            self.acks[index] = true;
            self.ack_reading[index] = false;
        }
        Ok(())
    }
    pub(crate) const fn a_done(&self) -> bool {
        matches!(self.a_state, AState::Done)
    }
    pub(crate) fn next_wake(&self) -> Result<Instant> {
        if self.a_done() && self.acks_done {
            return self.schedule.at(22_000_000_000);
        }
        let now = Instant::now();
        if !self.a_done() {
            return Ok(self
                .schedule
                .at(9_000_000_000)?
                .max(now + Duration::from_micros(500)));
        }
        if !self.acks_done && !self.acks.iter().all(|got| *got) {
            return Ok(self
                .schedule
                .at(16_000_000_000)?
                .max(now + Duration::from_micros(500)));
        }
        self.schedule.at(18_000_000_000)
    }
}
