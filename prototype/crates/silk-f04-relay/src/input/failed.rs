//! One opaque failed-input owner. No HPKE, cover, source-tagged output or retry.
use super::{Sessions, WriteSlot};
use crate::{
    Result,
    schedule::Schedule,
    tls::{ReceiveProgress, RecordSize},
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

pub struct FailedSessions {
    sessions: Sessions,
    schedule: Rc<Schedule>,
    eligible: [bool; 32],
    received: [bool; 32],
    carry: Option<(usize, WriteSlot)>,
    done: bool,
}

#[cfg(test)]
mod tests;
impl FailedSessions {
    pub(super) fn new(
        mut sessions: Sessions,
        schedule: Rc<Schedule>,
        mut eligible: [bool; 32],
        received: [bool; 32],
        selected: Option<(usize, WriteSlot)>,
    ) -> Self {
        // The failed healthy parser's partial input cannot be reset or assigned
        // a new deadline. This owner may only start/resume its own discard read.
        for session in &mut sessions.entries {
            if matches!(
                session.transport.receive_progress(),
                ReceiveProgress::Partial { .. }
            ) {
                let _ = session.transport.quarantine();
            }
        }
        let carry = selected.and_then(|(index, writer)| {
            if index >= sessions.entries.len() || !writer.selected() {
                None
            } else if writer.complete() {
                eligible[index] = true;
                None
            } else {
                Some((index, writer))
            }
        });
        Self {
            sessions,
            schedule,
            eligible,
            received,
            carry,
            done: false,
        }
    }
    /// An unstarted proposal still owns its original sessions. No client got
    /// this round's manifest, so any arriving input is unavailable/unsolicited.
    pub(crate) fn unmanifested(sessions: Sessions, schedule: Rc<Schedule>) -> Self {
        Self::new(sessions, schedule, [false; 32], [false; 32], None)
    }
    pub(crate) fn poll(&mut self) -> Result<bool> {
        if self.done {
            return Ok(true);
        }
        self.schedule.clock_healthy()?;
        if let Some((index, writer)) = &mut self.carry {
            let link = &mut self.sessions.entries[*index].transport;
            match writer.resume(link) {
                Ok(false) => return Ok(false),
                Ok(true) => self.eligible[*index] = true,
                Err(_) => {
                    let _ = link.quarantine();
                }
            }
            self.carry = None;
        }
        let cutoff = self.schedule.at(9_500_000_000)?;
        if Instant::now() >= cutoff {
            // No selected read is renewed past the original input cutoff. A
            // quiet untouched read may retire; partial/excess/EOF is quarantined.
            for session in &mut self.sessions.entries {
                let link = &mut session.transport;
                if link.receive_progress() == ReceiveProgress::Failed {
                    continue;
                }
                let closed = match link.receive_progress() {
                    ReceiveProgress::Idle => true,
                    ReceiveProgress::WaitingZeroBytes => link.retire_expired_read().is_ok(),
                    _ => false,
                };
                if !closed || link.has_extra_bytes().unwrap_or(true) {
                    let _ = link.quarantine();
                }
            }
            self.done = true;
            return Ok(true);
        }
        if Instant::now() < self.schedule.at(0)? {
            return Ok(false);
        }
        for (index, session) in self.sessions.entries.iter_mut().enumerate() {
            if Instant::now() >= cutoff {
                break;
            }
            let link = &mut session.transport;
            if !self.eligible[index]
                || self.received[index]
                || link.receive_progress() == ReceiveProgress::Failed
            {
                continue;
            }
            if link.receive_progress() == ReceiveProgress::Idle
                && link.expect(RecordSize::Cell, cutoff).is_err()
            {
                let _ = link.quarantine();
                continue;
            }
            // Existing selection is necessarily an original input read; never
            // reuse a Join/control cursor or extend its immutable deadline.
            if link.selected_read() != Some((RecordSize::Cell, cutoff)) {
                let _ = link.quarantine();
                continue;
            }
            match link.read_step() {
                Ok(Some(_bytes)) => self.received[index] = true,
                Ok(None) => (),
                Err(_) => {
                    let _ = link.quarantine();
                }
            }
        }
        Ok(false)
    }
    pub(crate) fn next_wake(&self) -> Result<Instant> {
        let soon = Instant::now() + Duration::from_micros(500);
        if self.carry.is_some() {
            return Ok(soon);
        }
        if self.done {
            return self.schedule.at(22_000_000_000);
        }
        if self.sessions.entries.iter().enumerate().all(|(i, s)| {
            !self.eligible[i]
                || self.received[i]
                || s.transport.receive_progress() == ReceiveProgress::Failed
        }) {
            return self.schedule.at(9_500_000_000);
        }
        Ok(self.schedule.at(0)?.max(soon))
    }
    pub(crate) fn finish(self) -> Result<Sessions> {
        if !self.done {
            return Err(crate::Error::Unavailable("A failed ingress still owned"));
        }
        Ok(self.sessions)
    }
}
