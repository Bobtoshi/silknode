//! Failed rounds retain their already selected write and service only the
//! remaining allocated control slots. No replacement ciphertext or new slot.
use crate::{
    Error, Result,
    flow::WriteSlot,
    owner::LiveCancel,
    schedule::Schedule,
    tls::{RecordSize, Transport},
};
use std::{rc::Rc, time::Instant};

/// An irreversible decision may finish only ciphertext already selected for
/// its original socket/deadline. This owner contains no key, signer or new-slot
/// authority and cannot retry a missing release on another producer connection.
pub(crate) struct CommittedWrite {
    carry: Option<(usize, WriteSlot)>,
    connections: Vec<u64>,
    unavailable: u8,
}
impl CommittedWrite {
    pub(crate) fn new(writer: WriteSlot, lane: usize, connections: Vec<u64>) -> Self {
        Self {
            carry: (writer.selected() && !writer.complete()).then_some((lane, writer)),
            connections,
            unavailable: 0,
        }
    }
    pub(crate) fn poll(&mut self, links: &mut [&mut Transport]) -> Result<bool> {
        if links.len() != self.connections.len()
            || links
                .iter()
                .zip(&self.connections)
                .any(|(link, id)| link.id() != *id)
        {
            return Err(Error::Unavailable("committed write connection replaced"));
        }
        if let Some((lane, writer)) = &mut self.carry {
            match writer.resume(links[*lane]) {
                Ok(false) => return Ok(false),
                Ok(true) => (),
                Err(_) => {
                    self.unavailable |= 1 << *lane;
                    let _ = links[*lane].quarantine();
                }
            }
            self.carry = None;
        }
        Ok(true)
    }
}

struct Slot {
    lane: usize,
    interval: (i64, i64),
}

/// Bounded output service for one durably aborted established round. It owns no
/// data batch/key, and cannot make a new signing or connection decision.
pub struct FailedControls {
    schedule: Rc<Schedule>,
    cancel: LiveCancel,
    slots: Vec<Slot>,
    next: usize,
    writer: WriteSlot,
    carry: Option<(usize, WriteSlot)>,
    connections: Vec<u64>,
    unavailable: u8,
    completed: u32,
}
impl FailedControls {
    #[allow(clippy::too_many_arguments)] // Complete transfer of one selected slot, not independent flags.
    fn new(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        slots: Vec<Slot>,
        next: usize,
        previous: WriteSlot,
        previous_lane: usize,
        previous_is_control: bool,
        connections: Vec<u64>,
    ) -> Self {
        let selected = previous.selected();
        let carry = (selected && !previous.complete()).then_some((previous_lane, previous));
        Self {
            schedule,
            cancel,
            slots,
            next: next + usize::from(selected && previous_is_control),
            writer: WriteSlot::default(),
            carry,
            connections,
            unavailable: 0,
            completed: 0,
        }
    }
    pub(crate) fn source(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        next: usize,
        previous: WriteSlot,
        previous_is_control: bool,
        connection: u64,
    ) -> Self {
        Self::new(
            schedule,
            cancel,
            vec![
                Slot {
                    lane: 0,
                    interval: (11_000_000_000, 14_000_000_000),
                },
                Slot {
                    lane: 0,
                    interval: (19_000_000_000, 19_750_000_000),
                },
            ],
            next,
            previous,
            0,
            previous_is_control,
            vec![connection],
        )
    }
    pub(crate) fn source_early(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        proposal: WriteSlot,
        connection: u64,
    ) -> Self {
        Self::new(
            schedule,
            cancel,
            vec![
                Slot {
                    lane: 0,
                    interval: (-10_000_000_000, -9_000_000_000),
                },
                Slot {
                    lane: 0,
                    interval: (11_000_000_000, 14_000_000_000),
                },
                Slot {
                    lane: 0,
                    interval: (19_000_000_000, 19_750_000_000),
                },
            ],
            0,
            proposal,
            0,
            true,
            vec![connection],
        )
    }
    pub(crate) fn producer(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        previous: WriteSlot,
        ack_finished: bool,
        connection: u64,
    ) -> Self {
        Self::new(
            schedule,
            cancel,
            vec![Slot {
                lane: 0,
                interval: (17_000_000_000, 18_000_000_000),
            }],
            usize::from(ack_finished),
            previous,
            0,
            !ack_finished,
            vec![connection],
        )
    }
    pub(crate) fn exit(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        next: usize,
        previous: WriteSlot,
        previous_lane: usize,
        previous_is_control: bool,
        connections: [u64; 4],
    ) -> Self {
        let mut slots = Vec::with_capacity(25);
        slots.push(Slot {
            lane: 0,
            interval: (14_000_000_000, 14_125_000_000),
        });
        for lane in 1..=3 {
            for _ in 0..2 {
                slots.push(Slot {
                    lane,
                    interval: (14_125_000_000, 15_000_000_000),
                });
            }
        }
        for i in 0..3 {
            let start = 18_000_000_000 + i * 125_000_000;
            slots.push(Slot {
                lane: 0,
                interval: (start, start + 125_000_000),
            });
        }
        for i in 0..3 {
            for lane in 1..=3 {
                let start = 18_500_000_000 + i * 125_000_000;
                slots.push(Slot {
                    lane,
                    interval: (start, start + 125_000_000),
                });
            }
        }
        for lane in 1..=3 {
            slots.push(Slot {
                lane,
                interval: (20_000_000_000, 20_125_000_000),
            });
        }
        for lane in 1..=3 {
            slots.push(Slot {
                lane,
                interval: (20_125_000_000, 21_000_000_000),
            });
        }
        Self::new(
            schedule,
            cancel,
            slots,
            next,
            previous,
            previous_lane,
            previous_is_control,
            connections.to_vec(),
        )
    }
    pub(crate) fn exit_early(
        schedule: Rc<Schedule>,
        cancel: LiveCancel,
        previous: WriteSlot,
        previous_lane: usize,
        is_response: bool,
        connections: [u64; 4],
    ) -> Self {
        // Delivery is entered only AFTER the response was completely written.
        // Its selected producer-manifest carry cannot reopen that control slot.
        let skip_response = !is_response || previous.selected();
        let mut service = Self::exit(
            schedule,
            cancel,
            0,
            previous,
            previous_lane,
            false,
            connections,
        );
        service.slots.insert(
            0,
            Slot {
                lane: 0,
                interval: (-9_000_000_000, -8_000_000_000),
            },
        );
        service.next = usize::from(skip_response);
        service
    }
    /// Progress at most one old selected record or one fixed failure-control
    /// slot. An unusable link is quarantined and reported as silence, not retried.
    /// # Errors
    /// Refuses changed connection identity, unhealthy clock or malformed local state.
    pub fn poll(&mut self, links: &mut [&mut Transport]) -> Result<bool> {
        if links.len() != self.connections.len()
            || links
                .iter()
                .zip(&self.connections)
                .any(|(t, id)| t.id() != *id)
        {
            return Err(Error::Unavailable("failed-round connection replaced"));
        }
        self.schedule.clock_healthy()?;
        if let Some((lane, writer)) = &mut self.carry {
            match writer.resume(links[*lane]) {
                Ok(false) => return Ok(false),
                Ok(true) => (),
                Err(_) => {
                    self.unavailable |= 1 << *lane;
                    let _ = links[*lane].quarantine();
                }
            }
            self.carry = None;
            return Ok(false);
        }
        let Some(slot) = self.slots.get(self.next) else {
            return Ok(true);
        };
        if Instant::now() < self.schedule.at(slot.interval.0)? {
            return Ok(false);
        }
        if self.unavailable & (1 << slot.lane) != 0
            || Instant::now() >= self.schedule.at(slot.interval.1)?
        {
            if self.writer.selected() && !self.writer.complete() {
                self.unavailable |= 1 << slot.lane;
                let _ = links[slot.lane].quarantine();
            }
            self.next += 1;
            self.writer = WriteSlot::default();
            return Ok(false);
        }
        match self.writer.poll(
            links[slot.lane],
            &self.schedule,
            slot.interval,
            RecordSize::Control,
            self.cancel.control().bytes(),
        ) {
            Ok(false) => return Ok(false),
            Ok(true) => self.completed |= 1 << self.next,
            Err(_) => {
                self.unavailable |= 1 << slot.lane;
                let _ = links[slot.lane].quarantine();
            }
        }
        self.next += 1;
        self.writer = WriteSlot::default();
        Ok(false)
    }
    /// Locally completed CANCEL writes only; not peer receipt or cancellation of
    /// exposure. Unavailable/expired slots are never represented as delivered.
    #[must_use]
    pub const fn completed_mask(&self) -> u32 {
        self.completed
    }
    /// Quarantined lane bitset, for explicit silence reporting.
    #[must_use]
    pub const fn unavailable_mask(&self) -> u8 {
        self.unavailable
    }

    /// Idle waits do not charge a 500us busy loop to the native CPU lease.
    pub(crate) fn next_wake(&self) -> Result<Instant> {
        let soon = Instant::now() + std::time::Duration::from_micros(500);
        if self.carry.is_some() {
            return Ok(soon);
        }
        self.slots.get(self.next).map_or_else(
            || self.schedule.at(22_000_000_000),
            |slot| Ok(self.schedule.at(slot.interval.0)?.max(soon)),
        )
    }
}
