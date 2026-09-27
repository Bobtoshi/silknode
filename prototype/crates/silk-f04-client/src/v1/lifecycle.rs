//! Bounded client process continuity; no cold replay or payment-driven reconnect.
use super::enrollment::{Window, enrollment_bytes};
use super::{
    ClientV1, Digest, EnrollmentProgressV1, EnrollmentV1, Error, LocalViewV1, OutcomeV1,
    QualifiedClockSample, Rc, Result, SavedOfferV1, Schedule, SignedConfig, Zeroizing,
};
use silk_f04_relay::tls::ClientProfile;

#[derive(Clone, Copy)]
enum Purpose {
    Repair(Digest),
    Epoch,
}
struct Attempt {
    enrollment: EnrollmentV1,
    purpose: Purpose,
}

/// One process owns at most two configurations, two live rounds/results total,
/// and two pending TCP/TLS/Join attempts. Its high-water never resets on install.
pub struct ProcessV1 {
    clients: [Option<ClientV1>; 2],
    pending: [Option<Attempt>; 2],
    highest: Option<u64>,
    repair_claim: Option<(Digest, u64)>,
    epoch_claim: Option<(Digest, u64)>,
}
impl ProcessV1 {
    /// Consume the actually joined baseline owner without discarding its history.
    #[must_use]
    pub const fn new(client: ClientV1) -> Self {
        let highest = client.highest;
        Self {
            clients: [Some(client), None],
            pending: [None, None],
            highest,
            repair_claim: None,
            epoch_claim: None,
        }
    }
    /// Admit one original round in an installed configuration. The offer is
    /// consumed even on failure; installing a connection never carries an offer.
    /// # Errors
    /// Refuses unknown/stale contexts, nonconsecutive overlap or global capacity.
    pub fn admit(
        &mut self,
        config: Digest,
        schedule: Schedule,
        view: LocalViewV1,
        offer: Option<SavedOfferV1>,
    ) -> Result<()> {
        let round = schedule.round();
        if self.highest.is_some_and(|r| round <= r)
            || self.occupied() >= 2
            || self
                .clients
                .iter()
                .flatten()
                .flat_map(|c| c.rounds.iter().flatten())
                .any(|r| r.schedule.round().checked_add(1) != Some(round))
        {
            return Err(Error::Unavailable(
                "client process stale/full/nonconsecutive round",
            ));
        }
        let client = self
            .clients
            .iter_mut()
            .flatten()
            .find(|c| c.config.id() == config)
            .ok_or(Error::Unavailable("client process unknown configuration"))?;
        if !client.config.contains_round(round) || round < client.eligible {
            return Err(Error::Unavailable(
                "client process foreign/ineligible round",
            ));
        }
        self.highest = Some(round);
        client.admit(schedule, view, offer)
    }
    fn occupied(&self) -> usize {
        self.clients
            .iter()
            .flatten()
            .map(|c| c.rounds.iter().flatten().count() + c.outcomes.iter().flatten().count())
            .sum()
    }
    /// Explicitly attempt a failed connection once during its original +24..+28.
    /// Taking the +22 outcome does not destroy this retained window. The repaired
    /// link is eligible at r+2 only, and cannot replace any old round snapshot.
    /// # Errors
    /// Refuses healthy/pending/already-attempted endpoints, late/foreign windows
    /// or r+2 crossing the configuration boundary. Failure consumes the claim.
    pub fn repair(&mut self, config: Digest, sample: &QualifiedClockSample) -> Result<()> {
        let client = self
            .clients
            .iter()
            .flatten()
            .find(|c| c.config.id() == config)
            .ok_or(Error::Unavailable("client repair configuration"))?;
        let schedule = client
            .last_closed
            .as_ref()
            .ok_or(Error::Unavailable("client repair original closed round"))?;
        schedule.observe_clock(sample)?;
        Window::Repair.check(schedule)?;
        let round = schedule.round();
        let eligible = round
            .checked_add(2)
            .filter(|r| client.config.contains_round(*r))
            .ok_or(Error::Unavailable(
                "client repair eligibility crosses epoch",
            ))?;
        if client.link.is_some()
            || self
                .repair_claim
                .is_some_and(|(id, r)| id == config && r >= round)
            || self
                .pending
                .iter()
                .flatten()
                .any(|a| matches!(a.purpose, Purpose::Repair(id) if id == config))
        {
            return Err(Error::Unavailable(
                "client repair healthy/already attempted",
            ));
        }
        let free = self
            .pending
            .iter_mut()
            .find(|a| a.is_none())
            .ok_or(Error::Unavailable("client pending setup capacity"))?;
        self.repair_claim = Some((config, round)); // Consume BEFORE the socket attempt.
        let enrollment = EnrollmentV1::begin(
            Rc::clone(&client.config),
            Zeroizing::new(*client.join),
            client.slot,
            client.profile.clone(),
            Rc::clone(schedule),
            Window::Repair,
            eligible,
        )?;
        *free = Some(Attempt {
            enrollment,
            purpose: Purpose::Repair(config),
        });
        Ok(())
    }
    /// Begin the immediately following epoch under the actual q-2 round's
    /// original 0..30 window. No manufactured schedule or old-round rescue.
    /// # Errors
    /// Refuses absent original authority, unretired configuration, duplicate
    /// attempt, bad configuration/roster/profile or expired setup. No retry follows.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_next(
        &mut self,
        bytes: &[u8; 770],
        roots: [Digest; 2],
        hashes: [Digest; 32],
        token: Zeroizing<[u8; 32]>,
        profile: ClientProfile,
        sample: &QualifiedClockSample,
    ) -> Result<()> {
        if self.clients.iter().flatten().count() != 1
            || self
                .pending
                .iter()
                .flatten()
                .any(|a| matches!(a.purpose, Purpose::Epoch))
        {
            return Err(Error::Unavailable("client next epoch capacity"));
        }
        let client = self
            .clients
            .iter()
            .flatten()
            .next()
            .ok_or(Error::Unavailable("client baseline absent"))?;
        let epoch = client
            .config
            .epoch()
            .checked_add(1)
            .ok_or(Error::Unavailable("client epoch overflow"))?;
        let first = u64::from(epoch) * 2880;
        let original = first - 2;
        let schedule = client
            .rounds
            .iter()
            .flatten()
            .map(|r| &r.schedule)
            .chain(client.last_closed.iter())
            .find(|s| s.round() == original)
            .ok_or(Error::Unavailable("client missing original q-2 lease"))?;
        schedule.observe_clock(sample)?;
        Window::NextEpoch.check(schedule)?;
        if self
            .epoch_claim
            .is_some_and(|(id, r)| id == client.config.id() && r >= original)
        {
            return Err(Error::Unavailable("client next epoch already attempted"));
        }
        let free = self
            .pending
            .iter_mut()
            .find(|a| a.is_none())
            .ok_or(Error::Unavailable("client pending setup capacity"))?;
        self.epoch_claim = Some((client.config.id(), original));
        let config = Rc::new(SignedConfig::verify(
            bytes,
            client.config.domain(),
            client.config.cohort(),
            epoch,
            roots,
        )?);
        let (join, slot) = enrollment_bytes(&config, hashes, token)?;
        let enrollment = EnrollmentV1::begin(
            config,
            join,
            slot,
            profile,
            Rc::clone(schedule),
            Window::NextEpoch,
            first,
        )?;
        *free = Some(Attempt {
            enrollment,
            purpose: Purpose::Epoch,
        });
        Ok(())
    }
    /// Bounded actual progress. Setup failure consumes its claim and drops its
    /// socket; it cannot restart a payment or replace a live round's connection.
    /// # Errors
    /// Refuses an internal capacity/context inconsistency; ordinary attempt failure
    /// leaves the failed endpoint unavailable until a later explicit fixed window.
    pub fn poll(&mut self, sample: &QualifiedClockSample) -> Result<()> {
        for client in self.clients.iter_mut().flatten() {
            client.poll(sample)?;
        }
        for slot in &mut self.pending {
            let Some(attempt) = slot.take() else { continue };
            match attempt.enrollment.poll(sample) {
                Ok(EnrollmentProgressV1::Pending(enrollment)) => {
                    *slot = Some(Attempt {
                        enrollment,
                        purpose: attempt.purpose,
                    });
                }
                Ok(EnrollmentProgressV1::Joined(mut ready)) => match attempt.purpose {
                    Purpose::Repair(id) => {
                        let client = self
                            .clients
                            .iter_mut()
                            .flatten()
                            .find(|c| c.config.id() == id)
                            .ok_or(Error::Unavailable("client repair owner missing"))?;
                        if client.link.is_some()
                            || ready.config.id() != id
                            || ready.slot != client.slot
                        {
                            return Err(Error::Unavailable("client repair install mismatch"));
                        }
                        client.link = ready.link.take();
                        client.eligible = ready.eligible;
                    }
                    Purpose::Epoch => {
                        let free = self
                            .clients
                            .iter_mut()
                            .find(|c| c.is_none())
                            .ok_or(Error::Unavailable("client epoch install capacity"))?;
                        *free = Some(ready);
                    }
                },
                Err(_) => (), // Original claim survives; no automatic reconnect.
            }
        }
        self.retire();
        Ok(())
    }
    fn retire(&mut self) {
        let newest = self
            .clients
            .iter()
            .flatten()
            .map(|c| c.config.epoch())
            .max();
        for slot in &mut self.clients {
            if slot.as_ref().is_some_and(|c| {
                Some(c.config.epoch()) < newest
                    && self
                        .highest
                        .is_some_and(|r| r >= (u64::from(c.config.epoch()) + 1) * 2880)
                    && c.rounds.iter().all(Option::is_none)
                    && c.outcomes.iter().all(Option::is_none)
            }) {
                *slot = None;
            }
        }
    }
    /// Consume the oldest fixed-time local result across both epochs. This does
    /// not reset high-water, release reserved inputs or create retry authority.
    pub fn take_outcome(&mut self) -> Option<OutcomeV1> {
        let (client, outcome, _) = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
            .flat_map(|(i, c)| {
                c.outcomes
                    .iter()
                    .enumerate()
                    .filter_map(move |(j, o)| o.map(|o| (i, j, o.round)))
            })
            .min_by_key(|(_, _, round)| *round)?;
        let result = self.clients[client].as_mut()?.outcomes[outcome].take();
        self.retire();
        result
    }
}

#[cfg(test)]
mod tests;
