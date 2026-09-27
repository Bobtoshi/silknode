//! Exact F0.4 full-data carriage and genuine pinned RandomX; no graph authority from decoding.
use crate::{Digest, Error, Result, budget::JobBudget, genesis::Genesis, wire::field};
use silk_order::sg0_v1::Sg0ParentSetV1;
use silk_pow::{Uint256, dag_randomx_v3::dag_target_for_work_v3, randomx_v2_work_key_id};
use silk_randomx::RandomXV2Vm;
use silk_sapling_f04::codec::{ENVELOPE_BYTES, Envelope, carriage_hash};
use silk_types::VertexId;

/// Maximum full canonical work-bearing vertex.
pub const MAX_VERTEX_BYTES: usize = 90_000;
const WORK_DOMAIN: &[u8] = b"SilkNode/PrivatePersistentDAG/RandomX/F0/v1\0";

/// Canonical typed parents, retaining big-endian carrier conventions.
pub fn encode_parents(parents: &Sg0ParentSetV1) -> Result<[u8; 68]> {
    let mut out = [0; 68];
    let p = parents.ordinary_parents();
    if let Sg0ParentSetV1::Vertices(ids) = parents {
        Sg0ParentSetV1::vertices(ids.clone())?;
    }
    if !p.is_empty() {
        out[0] = 1;
        out[1] = p.len() as u8;
        for (i, id) in p.iter().enumerate() {
            out[4 + 32 * i..36 + 32 * i].copy_from_slice(&id.into_bytes());
        }
    }
    Ok(out)
}
/// Representation validation only. SG-0 additionally establishes membership/incomparability.
pub fn decode_parents(bytes: &[u8; 68]) -> Result<Sg0ParentSetV1> {
    if bytes == &[0; 68] {
        return Ok(Sg0ParentSetV1::Anchor);
    }
    if bytes[0] != 1
        || !(1..=2).contains(&bytes[1])
        || bytes[2..4] != [0; 2]
        || (bytes[1] == 1 && bytes[36..] != [0; 32])
    {
        return Err(Error::Invalid("parent framing"));
    }
    let mut p = Vec::with_capacity(usize::from(bytes[1]));
    for i in 0..usize::from(bytes[1]) {
        p.push(VertexId::from_bytes(field(bytes, 4 + 32 * i)?));
    }
    Ok(Sg0ParentSetV1::vertices(p)?)
}

/// Unverified but canonically framed full body.
#[derive(Clone)]
pub struct Body {
    bytes: Vec<u8>,
    envelopes: Vec<[u8; ENVELOPE_BYTES]>,
}
impl Body {
    /// Construct a bounded body in producer-selected committed array order.
    pub fn new(domain: &Digest, envelopes: &[Envelope]) -> Result<Self> {
        if envelopes.len() > 32 {
            return Err(Error::Invalid("body count"));
        }
        let mut bytes = vec![0; 20 + ENVELOPE_BYTES * envelopes.len()];
        bytes[..8].copy_from_slice(b"SLKDGBF0");
        bytes[9] = 3;
        bytes[12] = envelopes.len() as u8;
        bytes[16..20].copy_from_slice(&((ENVELOPE_BYTES * envelopes.len()) as u32).to_be_bytes());
        for (i, e) in envelopes.iter().enumerate() {
            bytes[20 + ENVELOPE_BYTES * i..20 + ENVELOPE_BYTES * (i + 1)]
                .copy_from_slice(e.bytes());
        }
        Self::decode(&bytes, domain)
    }
    /// Pure framing before any work or elliptic-curve checks.
    pub fn decode(bytes: &[u8], _domain: &Digest) -> Result<Self> {
        if bytes.len() < 20
            || bytes.len() > 89_300
            || &bytes[..8] != b"SLKDGBF0"
            || bytes[8..12] != [0, 3, 0, 0]
            || bytes[12] > 32
            || bytes[13..16] != [0; 3]
        {
            return Err(Error::Invalid("body framing"));
        }
        let n = usize::from(bytes[12]);
        if bytes.len() != 20 + ENVELOPE_BYTES * n
            || u32::from_be_bytes(field(bytes, 16)?) as usize != ENVELOPE_BYTES * n
        {
            return Err(Error::Invalid("body length"));
        }
        let envelopes = bytes[20..]
            .chunks_exact(ENVELOPE_BYTES)
            .map(|e| e.try_into().expect("exact chunk"))
            .collect();
        Ok(Self {
            bytes: bytes.to_vec(),
            envelopes,
        })
    }
    /// Full exact body bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Framed, not yet cryptographically verified representations.
    #[must_use]
    pub fn representations(&self) -> &[[u8; ENVELOPE_BYTES]] {
        &self.envelopes
    }
    /// Exact ordered body/proof/recovery commitments and reward-bound body binding.
    #[must_use]
    pub fn commitments(&self, n: &Digest, owner: &Digest, nonce: &Digest) -> [Digest; 5] {
        let count = [self.envelopes.len() as u8];
        let mut proof_parts: Vec<&[u8]> = vec![n, &count];
        let mut recovery_parts: Vec<&[u8]> = vec![n, &count];
        for e in &self.envelopes {
            proof_parts.push(&e[1830..]);
            recovery_parts.push(&e[278..1790]);
        }
        let id = carriage_hash("SilkNode/F0-BodyId/v1", &[n, &self.bytes]);
        let proof = carriage_hash("SilkNode/F0-ProofSet/v1", &proof_parts);
        let recovery = carriage_hash("SilkNode/F0-Recovery/v1", &recovery_parts);
        let digest = carriage_hash("SilkNode/F0-BodyDigest/v1", &[n, &id, &proof, &recovery]);
        let binding = carriage_hash(
            "SilkNode/F0-BodyBinding/v1",
            &[n, &id, &digest, &proof, &recovery, owner, nonce],
        );
        [id, digest, proof, recovery, binding]
    }
}

/// Header claims. Only receiver derivation and work/proof checks can authenticate them.
#[derive(Clone, Debug)]
pub struct Header {
    /// Immutable exact header bytes.
    pub bytes: [u8; 592],
    /// Typed ordinary parents or configured genesis anchor.
    pub parents: Sg0ParentSetV1,
    /// Candidate Unix timestamp.
    pub timestamp: u64,
    /// Parent-local DAA epoch.
    pub epoch: u64,
    /// Parent-local DAA transcript commitment.
    pub daa: Digest,
    /// Required individual work, not cumulative work.
    pub work: u64,
    /// Delayed source checkpoint ordinal.
    pub source_index: u64,
    /// Exact branch-local source checkpoint ID.
    pub source_checkpoint: Digest,
    /// Exact branch-local J at that source.
    pub source_j: Digest,
    /// Raw seed, not key material or its ID.
    pub seed: Digest,
    /// Public nontransferable credit attribution tag.
    pub owner: Digest,
    /// Public reward nonce.
    pub reward_nonce: Digest,
}

/// Receiver-derived fields used to construct or compare a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentFacts {
    /// Exact B.4 184-byte source record, including the true maximal frontier.
    pub source_record: [u8; 184],
    /// DAA epoch.
    pub epoch: u64,
    /// Complete DAA transcript hash.
    pub daa: Digest,
    /// Individual required work.
    pub work: u64,
    /// Historical strict time lower bound.
    pub minimum_time: u64,
    /// Source ordinal.
    pub source_index: u64,
    /// Source checkpoint ID.
    pub source_checkpoint: Digest,
    /// Source eligible-prefix J.
    pub source_j: Digest,
    /// F0.4 source-derived raw seed.
    pub seed: Digest,
    /// F0.4 public RandomX key material.
    pub key_material: Digest,
}

impl Header {
    /// Construct exact new-profile bytes; claims still require independent receiver checks.
    pub fn new(
        genesis: &Genesis,
        parents: Sg0ParentSetV1,
        body: &Body,
        owner: Digest,
        reward_nonce: Digest,
        timestamp: u64,
        facts: &ParentFacts,
    ) -> Result<Self> {
        let mut b = [0; 592];
        b[..8].copy_from_slice(b"SLKMVH4\0");
        b[9] = 4;
        b[12..108].copy_from_slice(&genesis.context().bytes()[44..140]);
        b[108..176].copy_from_slice(&encode_parents(&parents)?);
        for (i, h) in body
            .commitments(&genesis.domain(), &owner, &reward_nonce)
            .iter()
            .enumerate()
        {
            b[176 + 32 * i..208 + 32 * i].copy_from_slice(h);
        }
        b[336..368].copy_from_slice(&owner);
        b[368..400].copy_from_slice(&reward_nonce);
        b[400..408].copy_from_slice(&timestamp.to_be_bytes());
        b[408..416].copy_from_slice(&facts.epoch.to_be_bytes());
        b[416..448].copy_from_slice(&facts.daa);
        b[448..456].copy_from_slice(&facts.work.to_be_bytes());
        b[456..464].copy_from_slice(&facts.source_index.to_be_bytes());
        b[464..496].copy_from_slice(&facts.source_checkpoint);
        b[496..528].copy_from_slice(&facts.source_j);
        b[528..560].copy_from_slice(&facts.seed);
        b[560..].copy_from_slice(&genesis.domain());
        Self::decode(b, body, genesis)
    }
    /// Check static context, representation and body bindings before work.
    pub fn decode(bytes: [u8; 592], body: &Body, genesis: &Genesis) -> Result<Self> {
        let b = &bytes;
        if &b[..8] != b"SLKMVH4\0"
            || b[8..12] != [0, 4, 0, 0]
            || b[12..108] != genesis.context().bytes()[44..140]
            || b[560..] != genesis.domain()
        {
            return Err(Error::Invalid("header profile/context"));
        }
        let owner = field(b, 336)?;
        let reward_nonce = field(b, 368)?;
        canonical_owner(&owner)?;
        for (i, expected) in body
            .commitments(&genesis.domain(), &owner, &reward_nonce)
            .iter()
            .enumerate()
        {
            if &b[176 + 32 * i..208 + 32 * i] != expected {
                return Err(Error::Invalid("body/header binding"));
            }
        }
        let work = u64::from_be_bytes(field(b, 448)?);
        if !(1..=1_000_000).contains(&work) {
            return Err(Error::Invalid("work range"));
        }
        Ok(Self {
            parents: decode_parents(&field(b, 108)?)?,
            timestamp: u64::from_be_bytes(field(b, 400)?),
            epoch: u64::from_be_bytes(field(b, 408)?),
            daa: field(b, 416)?,
            work,
            source_index: u64::from_be_bytes(field(b, 456)?),
            source_checkpoint: field(b, 464)?,
            source_j: field(b, 496)?,
            seed: field(b, 528)?,
            owner,
            reward_nonce,
            bytes,
        })
    }
    /// Reject every mismatched parent-derived claim, including historical time.
    pub fn check_facts(&self, f: &ParentFacts) -> Result<()> {
        if self.timestamp < f.minimum_time
            || self.epoch != f.epoch
            || self.daa != f.daa
            || self.work != f.work
            || self.source_index != f.source_index
            || self.source_checkpoint != f.source_checkpoint
            || self.source_j != f.source_j
            || self.seed != f.seed
        {
            return Err(Error::Invalid("parent-derived header facts"));
        }
        Ok(())
    }
}

fn canonical_owner(owner: &Digest) -> Result<()> {
    let modulus = hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000001")
        .expect("fixed field modulus");
    if owner.iter().rev().cmp(modulus.iter()) != std::cmp::Ordering::Less {
        return Err(Error::Invalid("noncanonical reward owner"));
    }
    Ok(())
}

/// Canonically decoded but unadmitted full-data vertex.
#[derive(Clone)]
pub struct Candidate {
    /// Claimed ID, never authoritative by itself.
    pub id: Digest,
    /// Exact statically bound header.
    pub header: Header,
    /// Complete canonical body.
    pub body: Body,
    /// Exact 52-byte work proof.
    pub proof: [u8; 52],
}
impl Candidate {
    /// Reject total length/shape before body allocations or curve work.
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self> {
        if bytes.len() < 720
            || bytes.len() > MAX_VERTEX_BYTES
            || &bytes[..8] != b"SLKMNDV4"
            || bytes[8..12] != [0, 4, 0, 0]
            || u32::from_be_bytes(field(bytes, 44)?) != 592
            || u32::from_be_bytes(field(bytes, 52)?) != 52
        {
            return Err(Error::Invalid("full vertex framing"));
        }
        let length = u32::from_be_bytes(field(bytes, 48)?) as usize;
        if bytes.len() != 56 + 592 + length + 52 {
            return Err(Error::Invalid("full vertex lengths"));
        }
        let body = Body::decode(&bytes[648..648 + length], &genesis.domain())?;
        let header = Header::decode(field(bytes, 56)?, &body, genesis)?;
        let proof = field(bytes, 648 + length)?;
        if &proof[..8] != b"SLKDPOW4" || proof[8..12] != [0, 4, 0, 0] {
            return Err(Error::Invalid("work proof framing"));
        }
        Ok(Self {
            id: field(bytes, 12)?,
            header,
            body,
            proof,
        })
    }
    /// Exact full bytes for archive/sync; no omitted proof or ciphertext sidecars.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(700 + self.body.bytes.len());
        b.extend_from_slice(b"SLKMNDV4\0\x04\0\0");
        b.extend_from_slice(&self.id);
        b.extend_from_slice(&592_u32.to_be_bytes());
        b.extend_from_slice(&(self.body.bytes.len() as u32).to_be_bytes());
        b.extend_from_slice(&52_u32.to_be_bytes());
        b.extend_from_slice(&self.header.bytes);
        b.extend_from_slice(&self.body.bytes);
        b.extend_from_slice(&self.proof);
        b
    }
}

/// One owning-thread RandomX VM/cache. Library-created background threads are absent.
pub struct WorkEngine {
    current: Option<(Digest, RandomXV2Vm)>,
}
impl Default for WorkEngine {
    fn default() -> Self {
        Self { current: None }
    }
}
impl WorkEngine {
    fn hash(&mut self, key: Digest, input: &[u8]) -> Result<Digest> {
        if self.current.as_ref().is_none_or(|(k, _)| *k != key) {
            self.current = Some((
                key,
                RandomXV2Vm::new(&key).map_err(|_| Error::Unavailable("RandomX initialization"))?,
            ));
        }
        self.current
            .as_mut()
            .expect("initialized VM")
            .1
            .calculate_hash(input)
            .map_err(|_| Error::Unavailable("RandomX evaluation"))
    }
    /// Genuine new-profile work; caller must have checked parent facts first.
    pub(crate) fn verify(
        &mut self,
        c: &Candidate,
        f: &ParentFacts,
        genesis: &Genesis,
    ) -> Result<()> {
        c.header.check_facts(f)?;
        let nonce = u64::from_be_bytes(field(&c.proof, 12)?);
        let actual = self.hash(
            f.key_material,
            &work_input(&c.header, genesis, f.key_material, nonce)?,
        )?;
        if actual != field::<32>(&c.proof, 20)? || Uint256::from_be_bytes(actual) > target(f.work)?
        {
            return Err(Error::Invalid("RandomX result/target"));
        }
        if c.id != vertex_id(&c.header, &c.proof, genesis, f.key_material)? {
            return Err(Error::Invalid("claimed vertex ID"));
        }
        Ok(())
    }
    /// Mine genuinely, pausing on a bounded local deadline rather than weakening work.
    pub(crate) fn mine(
        &mut self,
        header: Header,
        body: Body,
        genesis: &Genesis,
        f: &ParentFacts,
        budget: &JobBudget,
    ) -> Result<Candidate> {
        let header = Header::decode(header.bytes, &body, genesis)?;
        header.check_facts(f)?;
        let t = target(f.work)?;
        for nonce in 0..u64::MAX {
            budget.check()?;
            let hash = self.hash(
                f.key_material,
                &work_input(&header, genesis, f.key_material, nonce)?,
            )?;
            // Cooperative boundary on every platform; the Linux coordinator's
            // original native lease also spans initialization/evaluation itself.
            budget.check()?;
            if Uint256::from_be_bytes(hash) <= t {
                let mut proof = [0; 52];
                proof[..8].copy_from_slice(b"SLKDPOW4");
                proof[9] = 4;
                proof[12..20].copy_from_slice(&nonce.to_be_bytes());
                proof[20..].copy_from_slice(&hash);
                let id = vertex_id(&header, &proof, genesis, f.key_material)?;
                return Ok(Candidate {
                    id,
                    header,
                    body,
                    proof,
                });
            }
        }
        Err(Error::Paused("nonce space"))
    }
}

fn target(work: u64) -> Result<Uint256> {
    dag_target_for_work_v3(work).map_err(|_| Error::Invalid("work target"))
}
fn work_input(header: &Header, genesis: &Genesis, key: Digest, nonce: u64) -> Result<Vec<u8>> {
    let policy = carriage_hash(
        "SilkNode/F0-Target/v1",
        &[b"floor(2^256/work)-1;work=1:2^256-1;work-range:1..1000000"],
    );
    let suite = carriage_hash(
        "SilkNode/F0-PoW-Suite/v1",
        &[
            b"RandomX-v2.0.1-aaafe71322df6602c21a5c72937ac284724ae561",
            WORK_DOMAIN,
            &policy,
            b"digest-big-endian;header592;proof4;interpreted-light",
        ],
    );
    let mut b = Vec::with_capacity(848);
    b.extend_from_slice(WORK_DOMAIN);
    b.extend_from_slice(&suite);
    b.extend_from_slice(&policy);
    b.extend_from_slice(&genesis.context().bytes()[44..108]);
    b.extend_from_slice(&randomx_v2_work_key_id(key));
    b.extend_from_slice(&header.work.to_be_bytes());
    b.extend_from_slice(&target(header.work)?.to_be_bytes());
    b.extend_from_slice(&592_u32.to_be_bytes());
    b.extend_from_slice(&header.bytes);
    b.extend_from_slice(&nonce.to_be_bytes());
    Ok(b)
}
fn vertex_id(header: &Header, proof: &[u8; 52], genesis: &Genesis, key: Digest) -> Result<Digest> {
    let template = carriage_hash(
        "SilkNode/F0-HeaderTemplate/v1",
        &[&work_input(header, genesis, key, 0)?],
    );
    Ok(carriage_hash(
        "SilkNode/F0-VertexId/v1",
        &[&template, proof],
    ))
}
