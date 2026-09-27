//! Bounded discard after a producer failure. This cursor never verifies a batch,
//! signs readiness, exposes payloads, or extends an already selected TLS read.
use crate::{
    Error, Result,
    config::SignedConfig,
    schedule::Schedule,
    tls::{ReceiveProgress, RecordSize, Transport},
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};
mod exit_input;
pub use exit_input::ExitInputDrain;

pub struct ProducerDrain {
    config: Rc<SignedConfig>,
    schedule: Rc<Schedule>,
    connection: u64,
    next: u8,
    reading: bool,
    done: bool,
}
impl ProducerDrain {
    pub(crate) const fn new(
        config: Rc<SignedConfig>,
        schedule: Rc<Schedule>,
        connection: u64,
        next: u8,
    ) -> Self {
        Self {
            config,
            schedule,
            connection,
            next,
            reading: false,
            done: false,
        }
    }
    /// One bounded receive step. A successor header is left entirely untouched;
    /// its own ordinary receiver must still authenticate the complete manifest.
    pub(crate) fn poll(
        &mut self,
        link: &mut Transport,
        successor: Option<(Instant, Instant)>,
    ) -> Result<bool> {
        if link.id() != self.connection {
            return Err(Error::Unavailable("producer drain connection replaced"));
        }
        if self.done {
            return Ok(true);
        }
        if let Err(_error) = self.advance(link, successor) {
            // Discard failure cannot rehabilitate or silently reset the stream.
            let _ = link.quarantine();
            self.done = true;
        }
        Ok(self.done)
    }
    #[allow(clippy::too_many_lines)]
    fn advance(
        &mut self,
        link: &mut Transport,
        successor: Option<(Instant, Instant)>,
    ) -> Result<()> {
        let now = Instant::now();
        let progress = link.receive_progress();
        if progress == ReceiveProgress::Failed
            || (!self.reading && matches!(progress, ReceiveProgress::Partial { .. }))
        {
            return Err(Error::Unavailable(
                "producer failed ingress already partial",
            ));
        }
        if let Some((_, deadline)) = link.selected_read()
            && now >= deadline
        {
            link.retire_expired_read()?; // Only zero consumed bytes may retire.
            self.reading = false;
        }
        if self.reading {
            if let Some(bytes) = link.read_step()? {
                let size = slot(self.next)?.0;
                self.check_discard(&bytes, size)?;
                self.next += 1;
                self.reading = false;
            }
            return Ok(());
        }
        // Skip only elapsed receive windows. Skipping is not evidence that a
        // record was received, and never relaxes the physical transcript cap.
        while self.next < 40 && now >= self.schedule.at(slot(self.next)?.2)? {
            self.next += 1;
        }
        let header = link.peek_record_size()?;
        if header == Some(RecordSize::Manifest) && self.next != 0 {
            let (start, end) =
                successor.ok_or(Error::Unavailable("producer unexpected next manifest"))?;
            if now < start || now >= end {
                return Err(Error::Unavailable(
                    "producer next manifest outside original window",
                ));
            }
            if let Some((size, _)) = link.selected_read() {
                link.retire_empty(size)?;
            }
            self.done = true;
            return Ok(());
        }
        if now >= self.schedule.at(21_000_000_000)? || self.next == 40 {
            // A partial unconsumed header is not quietness. Late old records
            // cannot be mistaken for a subsequent manifest.
            if link.has_extra_bytes()? {
                return Err(Error::Unavailable("producer excess/late failed transcript"));
            }
            self.done = now >= self.schedule.at(21_000_000_000)?;
            return Ok(());
        }
        let Some(size) = header else {
            return Ok(());
        };
        // Failed B may omit data, but CANCEL occupies control slots only.
        if (3..35).contains(&self.next) && size == RecordSize::Control {
            if let Some((selected, _)) = link.selected_read() {
                link.retire_empty(selected)?;
            }
            self.next = 35;
        } else if (1..3).contains(&self.next) && size == RecordSize::Cell {
            if let Some((selected, _)) = link.selected_read() {
                link.retire_empty(selected)?;
            }
            self.next = 3;
        }
        let (expected, start, end) = slot(self.next)?;
        if now < self.schedule.at(start)? {
            return Ok(());
        }
        if size != expected {
            return Err(Error::Invalid("producer failed transcript class"));
        }
        if let Some((selected, _)) = link.selected_read() {
            if selected != size {
                return Err(Error::Invalid("producer selected drain class"));
            }
        } else {
            link.expect(size, self.schedule.at(end)?)?;
        }
        self.reading = true;
        if let Some(bytes) = link.read_step()? {
            self.check_discard(&bytes, size)?;
            self.next += 1;
            self.reading = false;
        }
        Ok(())
    }
    fn check_discard(&self, bytes: &[u8], size: RecordSize) -> Result<()> {
        let context = match size {
            RecordSize::Manifest => {
                bytes.get(8..40) == Some(self.config.domain().as_slice())
                    && crate::u64le(bytes, 44)? == self.schedule.round()
            }
            RecordSize::Control => {
                bytes.get(12..44) == Some(self.config.domain().as_slice())
                    && bytes.get(44..76) == Some(self.config.id().as_slice())
                    && crate::u64le(bytes, 80)? == self.schedule.round()
            }
            RecordSize::Cell => {
                bytes.get(20..52) == Some(self.config.domain().as_slice())
                    && crate::u64le(bytes, 12)? == self.schedule.round()
            }
            RecordSize::Join => false,
        };
        if !context {
            return Err(Error::Invalid("producer failed discard context"));
        }
        Ok(())
    }
    pub(crate) fn next_wake(&self) -> Result<Instant> {
        let soon = Instant::now() + Duration::from_micros(500);
        if self.done {
            return self.schedule.at(22_000_000_000);
        }
        if self.reading || self.next == 40 {
            return Ok(soon);
        }
        Ok(self.schedule.at(slot(self.next)?.1)?.max(soon))
    }
}

fn slot(next: u8) -> Result<(RecordSize, i64, i64)> {
    Ok(match next {
        0 => (RecordSize::Manifest, -9_000_000_000, 1_000_000_000),
        1..=2 => (RecordSize::Control, 13_125_000_000, 15_000_000_000),
        3..=34 => (
            RecordSize::Cell,
            14_000_000_000 + i64::from(next - 3) * 31_250_000,
            17_000_000_000,
        ),
        35..=37 => (
            RecordSize::Control,
            17_500_000_000 + i64::from(next - 35) * 125_000_000,
            20_000_000_000,
        ),
        38 => (RecordSize::Control, 19_000_000_000, 21_000_000_000),
        39 => (RecordSize::Control, 19_125_000_000, 21_000_000_000),
        _ => return Err(Error::Unavailable("producer drain cursor exhausted")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_discard_plan_has_only_original_bounded_slots() {
        let mut counts = [0; 3];
        for next in 0..40 {
            let (size, start, end) = slot(next).unwrap();
            assert!(start < end && end <= 21_000_000_000);
            match size {
                RecordSize::Manifest => counts[0] += 1,
                RecordSize::Control => counts[1] += 1,
                RecordSize::Cell => counts[2] += 1,
                RecordSize::Join => panic!("no setup slot in round"),
            }
        }
        assert_eq!(counts, [1, 7, 32]);
        assert!(slot(40).is_err());
    }
}
