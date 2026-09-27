//! Volatile consumed-once adapter. No durable delivery, automatic retry, resume,
//! default endpoint or promise of eventual canonical inclusion.
use crate::{
    Digest, Error, Result,
    carriage::{Body, Candidate},
    node::{Ingress, Node, NodeStatus},
};
use silk_sapling_f04::{
    codec::{ENVELOPE_BYTES, EnvelopeView},
    parameters::SaplingParameters,
};

/// At most one released batch's real envelopes in exact producer-selected order.
///
/// Construction checks framing only, NOT relay provenance, proofs or spentness.
/// Local process/file custody must be established separately; a decoded body is
/// never a substitute for the actual relay release capability.
pub struct LocalOfferV1 {
    domain: Digest,
    envelopes: Box<[[u8; ENVELOPE_BYTES]]>,
}
impl LocalOfferV1 {
    /// Admit bounded exact local bytes without granting ledger or relay authority.
    /// # Errors
    /// Refuses more than32 envelopes, wrong framing or foreign N before any work.
    pub fn from_local_payloads(
        domain: Digest,
        envelopes: Vec<[u8; ENVELOPE_BYTES]>,
    ) -> Result<Self> {
        if envelopes.len() > 32 {
            return Err(Error::Invalid("local offer count"));
        }
        for bytes in &envelopes {
            EnvelopeView::decode(bytes, &domain)?;
        }
        Ok(Self {
            domain,
            envelopes: envelopes.into_boxed_slice(),
        })
    }
    /// Raw-envelope bytes retained, excluding fixed public metadata.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.envelopes.len() * ENVELOPE_BYTES
    }

    /// Consume into the existing bounded canonical body encoding for explicit
    /// LOCAL process handoff. File/pipe custody must be provided separately.
    /// These bytes carry no assertion that a relay executed or authorized them.
    /// # Errors
    /// Refuses an internal body framing/count inconsistency.
    pub fn encode_local(self) -> Result<Vec<u8>> {
        let bytes = self.body()?.bytes().to_vec();
        drop(self);
        Ok(bytes)
    }
    /// Decode the same fixed maximum89300-byte local body without proving relay
    /// provenance or admitting a vertex. This is NOT a public ingress endpoint.
    /// # Errors
    /// Refuses body/envelope framing, excess size/count or a foreign domain.
    pub fn decode_local(bytes: &[u8], expected_domain: Digest) -> Result<Self> {
        let body = Body::decode(bytes, &expected_domain)?;
        Self::from_local_payloads(expected_domain, body.representations().to_vec())
    }

    /// Consume this offer for at most ONE ordinary-current-time mining attempt.
    /// Execute in the separately contained node runtime, never the relay process
    /// or its original two-second/128-MiB lease. No proof generation is performed.
    /// # Errors
    /// Refuses a foreign/unready node or ordinary mining failure. The offer is
    /// dropped on every failure; the existing `ACTIVE_JOB` rules still apply.
    pub fn mine_current(
        self,
        node: &mut Node,
        reward_owner: Digest,
        reward_nonce: Digest,
    ) -> Result<ProducedV1> {
        let Some(body) = self.into_body(node.genesis().domain(), node.status()?)? else {
            return Ok(ProducedV1::NoPayment);
        };
        let candidate = node.mine_current(body, reward_owner, reward_nonce, None)?;
        Ok(ProducedV1::Candidate(ProducedCandidateV1(Box::new(
            candidate,
        ))))
    }
    fn into_body(self, domain: Digest, status: NodeStatus) -> Result<Option<Body>> {
        if self.domain != domain {
            return Err(Error::Invalid("local offer foreign node"));
        }
        if status != NodeStatus::Ready {
            return Err(Error::Paused("reconcile before local offer"));
        }
        if self.envelopes.is_empty() {
            return Ok(None);
        }
        let body = self.body()?;
        drop(self);
        Ok(Some(body))
    }
    fn body(&self) -> Result<Body> {
        let payload_size = self.payload_bytes();
        let mut bytes = vec![0; 20 + payload_size];
        bytes[..8].copy_from_slice(b"SLKDGBF0");
        bytes[9] = 3;
        bytes[12] =
            u8::try_from(self.envelopes.len()).map_err(|_| Error::Invalid("local offer count"))?;
        bytes[16..20].copy_from_slice(
            &u32::try_from(payload_size)
                .map_err(|_| Error::Invalid("local offer bytes"))?
                .to_be_bytes(),
        );
        for (i, envelope) in self.envelopes.iter().enumerate() {
            bytes[20 + i * ENVELOPE_BYTES..20 + (i + 1) * ENVELOPE_BYTES].copy_from_slice(envelope);
        }
        Body::decode(&bytes, &self.domain)
    }
}

/// Cover-only does not manufacture work or a checkpoint.
pub enum ProducedV1 {
    /// No real envelopes; nothing was mined.
    NoPayment,
    /// Exact locally mined candidate, not yet graph admission.
    Candidate(ProducedCandidateV1),
}
/// One exact candidate; loss before ingress is a dropped volatile offer, not
/// permission to regenerate work. No Clone, saved-job restore or mining loop.
pub struct ProducedCandidateV1(Box<Candidate>);
impl ProducedCandidateV1 {
    /// Exact already-mined bytes for explicit local retention/ordinary ingress.
    /// This is not a provenance, proof-validity or acceptance receipt.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    /// Consume this candidate through the ordinary receiver and its original
    /// bounded continuation. No retry sleeps, renewed mining or implicit state
    /// reconciliation. The caller independently retains the returned head pin.
    /// # Errors
    /// Ordinary ingress/storage/resource refusal consumes this wrapper. A prior
    /// explicit copy, if any, has only the ordinary raw-ingress authority.
    pub fn ingest(
        self,
        node: &mut Node,
        parameters: &SaplingParameters,
    ) -> Result<AdmissionReceiptV1> {
        let vertex = self.0.id;
        let ingress = node.ingest(&self.0.encode(), parameters)?;
        Ok(AdmissionReceiptV1 {
            vertex,
            ingress,
            status: node.status()?,
            local_head: node.local_head()?,
        })
    }
}
/// Graph admission and continuity only. Canonical wallet effects remain separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionReceiptV1 {
    /// Exact candidate ID, not an effect/transaction confirmation.
    pub vertex: Digest,
    /// Ordinary admitted/already-known receiver result.
    pub ingress: Ingress,
    /// May require explicit bounded `Node::advance` reconciliation.
    pub status: NodeStatus,
    /// Retain independently before relying on a subsequent pinned reopen.
    pub local_head: Digest,
}

#[cfg(test)]
mod tests;
