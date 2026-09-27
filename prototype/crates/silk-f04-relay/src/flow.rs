//! Single-coordinator fixed-slot I/O. No per-source queue or adaptive slot exists.
use crate::{
    Error, Result,
    schedule::Schedule,
    tls::{RecordSize, Transport},
};
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct WriteSlot {
    selected: Option<Selection>,
    complete: bool,
}
struct Selection {
    transport: u64,
    round: u64,
    interval: (i64, i64),
    size: RecordSize,
}
impl WriteSlot {
    pub(crate) fn poll(
        &mut self,
        transport: &mut Transport,
        schedule: &Schedule,
        interval: (i64, i64),
        size: RecordSize,
        bytes: &[u8],
    ) -> Result<bool> {
        if self.complete {
            return Ok(true);
        }
        if Instant::now() < schedule.at(interval.0)? {
            return Ok(false);
        }
        schedule.in_window(interval.0, interval.1)?;
        if let Some(selected) = &self.selected {
            if selected.transport != transport.id()
                || selected.round != schedule.round()
                || selected.interval != interval
                || selected.size != size
            {
                return Err(Error::Unavailable("selected write slot identity changed"));
            }
        } else {
            transport.queue(size, bytes, schedule.at(interval.1)?)?;
            self.selected = Some(Selection {
                transport: transport.id(),
                round: schedule.round(),
                interval,
                size,
            });
        }
        self.complete = transport.write_step()?;
        Ok(self.complete)
    }
    pub(crate) const fn selected(&self) -> bool {
        self.selected.is_some()
    }
    pub(crate) const fn complete(&self) -> bool {
        self.complete
    }
    /// Finish only the already encrypted record with its original transport and
    /// deadline. Failure handling cannot replace it even at zero written bytes.
    pub(crate) fn resume(&mut self, transport: &mut Transport) -> Result<bool> {
        if self.complete {
            return Ok(true);
        }
        if self
            .selected
            .as_ref()
            .is_none_or(|s| s.transport != transport.id())
        {
            return Err(Error::Unavailable("no matching selected write to resume"));
        }
        self.complete = transport.write_step()?;
        Ok(self.complete)
    }
}

#[derive(Default)]
pub struct ReadSlot {
    selected: bool,
    complete: bool,
}
impl ReadSlot {
    pub(crate) fn poll(
        &mut self,
        transport: &mut Transport,
        schedule: &Schedule,
        interval: (i64, i64),
        size: RecordSize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if self.complete {
            return Err(Error::Unavailable("completed fixed read reused"));
        }
        if Instant::now() < schedule.at(interval.0)? {
            return Ok(None);
        }
        schedule.in_window(interval.0, interval.1)?;
        if !self.selected {
            transport.expect(size, schedule.at(interval.1)?)?;
            self.selected = true;
        }
        let received = transport.read_step()?;
        self.complete = received.is_some();
        Ok(received)
    }
}
