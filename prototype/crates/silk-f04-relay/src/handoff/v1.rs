//! One bounded producer offer queue. Queued offers are volatile, not delivery
//! promises; draining never invokes node work under a relay round's resource lease.
use crate::{
    Digest, Error, Result, config::SignedConfig, control::Role, frame::Payload,
    manifest::SignedManifest,
};
use silk_f04_node::offer::v1::LocalOfferV1;

/// Source metadata retained with an actual whole-batch release, not source/client
/// associations and not cryptographic evidence of participant honesty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryV1 {
    /// Exact ledger domain.
    pub domain: Digest,
    /// Fixed cohort.
    pub cohort: u32,
    /// Exact co-signed configuration hash.
    pub config: Digest,
    /// Exact co-signed manifest hash.
    pub manifest: Digest,
    /// Original release round.
    pub round: u64,
    /// Actual configured receiving producer.
    pub producer: Role,
}
/// Unforgeable through the public library API, non-Clone complete release.
/// Only the producer's actual completed release can construct this wrapper.
pub struct ReleasedBatchV1 {
    delivery: DeliveryV1,
    payloads: [Payload; 32],
}
impl ReleasedBatchV1 {
    pub(crate) const fn from_completed(
        config: &SignedConfig,
        manifest: &SignedManifest,
        producer: Role,
        payloads: [Payload; 32],
    ) -> Self {
        Self {
            delivery: DeliveryV1 {
                domain: config.domain(),
                cohort: config.cohort(),
                config: config.id(),
                manifest: manifest.id(),
                round: manifest.round(),
                producer,
            },
            payloads,
        }
    }
    /// Fixed public context only; this copy cannot construct another release.
    #[must_use]
    pub const fn delivery(&self) -> DeliveryV1 {
        self.delivery
    }
    /// Legacy whole-array consumer; still no ledger authority or automatic retry.
    #[must_use]
    pub fn into_payloads(self) -> [Payload; 32] {
        self.payloads
    }
}
struct Queued {
    delivery: DeliveryV1,
    offer: LocalOfferV1,
}
/// One fixed domain/cohort/producer queue, at most two complete batches and
///64 real envelopes (178560 raw bytes). No fee/nullifier ordering or retries.
pub struct ProducerInboxV1 {
    domain: Digest,
    cohort: u32,
    producer: Role,
    highest: Option<u64>,
    queue: [Option<Queued>; 2],
}
impl ProducerInboxV1 {
    /// Bind the sole queue to the producer's already accepted public context.
    /// # Errors
    /// Refuses a relay role; A/B cannot construct a producer ingress queue.
    pub const fn new(domain: Digest, cohort: u32, role: Role) -> Result<Self> {
        if !matches!(role, Role::P0 | Role::P1 | Role::P2) {
            return Err(Error::Invalid("producer inbox role"));
        }
        Ok(Self {
            domain,
            cohort,
            producer: role,
            highest: None,
            queue: [None, None],
        })
    }
    /// Consume one complete authorized release, preserving exact real bytes/order.
    /// Covers are excluded. Capacity refusal drops only this uncommitted offer;
    /// no existing queue entry or signed/durable ledger state is changed.
    /// # Errors
    /// Refuses foreign/replayed batches or the fixed two-batch capacity. Refused
    /// and successfully drained rounds cannot be automatically offered again.
    pub fn offer(&mut self, batch: ReleasedBatchV1) -> Result<()> {
        let delivery = batch.delivery;
        if delivery.domain != self.domain
            || delivery.cohort != self.cohort
            || delivery.producer != self.producer
            || self.highest.is_some_and(|r| delivery.round <= r)
        {
            return Err(Error::Unavailable("producer inbox foreign/replayed batch"));
        }
        self.highest = Some(delivery.round);
        let slot = self
            .queue
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::Unavailable(
                "producer inbox full; uncommitted offer dropped",
            ))?;
        let bytes = batch
            .payloads
            .into_iter()
            .filter_map(|p| p.real_bytes().copied())
            .collect();
        let offer = LocalOfferV1::from_local_payloads(delivery.domain, bytes)?;
        *slot = Some(Queued { delivery, offer });
        Ok(())
    }
    /// Raw queued payload-byte accounting; no staged ciphertext or metadata.
    #[must_use]
    pub fn payload_bytes(&self) -> usize {
        self.queue
            .iter()
            .flatten()
            .map(|q| q.offer.payload_bytes())
            .sum()
    }
    /// Consume the oldest offer before handing it to the separate node runtime.
    /// Nothing restores/requeues it on refusal, interruption, drop or restart.
    pub fn take_next(&mut self) -> Option<(DeliveryV1, LocalOfferV1)> {
        let index = self
            .queue
            .iter()
            .enumerate()
            .filter_map(|(i, q)| q.as_ref().map(|q| (i, q.delivery.round)))
            .min_by_key(|(_, round)| *round)?
            .0;
        self.queue[index].take().map(|q| (q.delivery, q.offer))
    }
}
