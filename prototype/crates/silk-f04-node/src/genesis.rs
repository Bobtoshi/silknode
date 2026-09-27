//! Acyclic F0.4 PB/G/AP/GD/X and signed allocation-receipt admission.
//!
//! Signatures attest the trusted allocation premise; they do not publicly prove
//! hidden initial supply or administrative independence. Operator acceptance is explicit.
use crate::{
    Digest, Error, Result,
    auth::{admit_role_key, verify_role_signature},
    wire::{field, prefixed_message, raw_hash, u32le, u64le},
};
use sapling_crypto::{CommitmentTree, Node};
use silk_sapling_f04::{
    codec::{Context, RECOVERY_BYTES, RULES_ID, carriage_hash, domain_hash},
    parameters::{OUTPUT_BLAKE2B, SPEND_BLAKE2B},
    wallet::{MAX_VALUE, RecoveryOutput},
};
use std::collections::BTreeSet;

pub mod public_testnet_v1;

/// Immutable profile parameters, in exact ascending ID order.
#[must_use]
pub fn parameter_bytes() -> [u8; 656] {
    let values: [u64; 32] = [
        2, 2, 10, 11, 32, 5, 15, 4, 2, 1, 1_000_000, 8, 10, 16, 128, 2, 4, 16, 4, 32, 128, 32, 8,
        64, 32, 2790, 32, MAX_VALUE, 1, 0, 0, 0,
    ];
    let mut b = [0; 656];
    b[..8].copy_from_slice(b"SNPARF01");
    b[8] = 1;
    b[12] = 32;
    for (i, v) in values.iter().enumerate() {
        let at = 16 + 16 * i;
        b[at..at + 2].copy_from_slice(&((i + 1) as u16).to_le_bytes());
        b[at + 8..at + 16].copy_from_slice(&v.to_le_bytes());
    }
    b[528..592].copy_from_slice(&hex::decode(SPEND_BLAKE2B).expect("fixed parameter digest"));
    b[592..656].copy_from_slice(&hex::decode(OUTPUT_BLAKE2B).expect("fixed parameter digest"));
    b
}

/// Complete public accepted-genesis material. Fields cannot be mutated after admission.
#[derive(Clone)]
pub struct Genesis {
    context: Context,
    descriptor: [u8; 244],
    allocation: Vec<u8>,
    policy: Vec<u8>,
    receipt: Vec<u8>,
    recoveries: Vec<[u8; RECOVERY_BYTES]>,
    total: u64,
    tree: CommitmentTree,
}

/// Exact derived descriptor/context before the N-dependent receipt exists.
pub struct GenesisDerivation {
    /// Fixed canonical GD bytes.
    pub descriptor: [u8; 244],
    /// Exact static context derived from GD/PB/G/AP.
    pub context: Context,
}

struct PreparedAttestations {
    domain: Digest,
    descriptor: Digest,
    policy: Digest,
    allocation: Digest,
    total: u64,
    entries: Vec<(Digest, u64)>,
}
impl PreparedAttestations {
    fn new(d: &GenesisDerivation, allocation: &[u8], policy: &[u8]) -> Result<Self> {
        let count = u32le(allocation, 16)? as usize;
        if !(1..=4096).contains(&count)
            || allocation.len() != 20 + 732 * count
            || policy.len() != 80 + 32 * count
        {
            return Err(Error::Invalid("attestation material framing"));
        }
        let hg = raw_hash(allocation);
        let aph = domain_hash("SilkNode-F01-genesis-audit-policy", &[policy]);
        if hg != field::<32>(&d.descriptor, 116)? || aph != field::<32>(&d.descriptor, 212)? {
            return Err(Error::Invalid("attestation genesis mismatch"));
        }
        let entries = allocation[20..]
            .chunks_exact(732)
            .map(|e| Ok((raw_hash(e), u64le(e, 0)?)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            domain: d.context.domain(),
            descriptor: raw_hash(&d.descriptor),
            policy: aph,
            allocation: hg,
            total: u64le(allocation, 8)?,
            entries,
        })
    }
    fn body(&self, role: u8, index: u32) -> Result<[u8; 184]> {
        let (entry, amount) = match role {
            0 | 1 if index == u32::MAX => (self.allocation, self.total),
            2 => *self
                .entries
                .get(index as usize)
                .ok_or(Error::Invalid("attestation role/index"))?,
            _ => return Err(Error::Invalid("attestation role/index")),
        };
        let mut b = [0; 184];
        b[..8].copy_from_slice(b"SNAGA001");
        b[8] = role;
        b[9] = 1;
        for (i, h) in [self.domain, self.descriptor, self.policy, self.allocation]
            .iter()
            .enumerate()
        {
            b[12 + 32 * i..44 + 32 * i].copy_from_slice(h);
        }
        b[140..144].copy_from_slice(&index.to_le_bytes());
        b[144..176].copy_from_slice(&entry);
        b[176..].copy_from_slice(&amount.to_le_bytes());
        Ok(b)
    }
}

impl GenesisDerivation {
    /// Derive public IDs without inventing a checkpoint or circular genesis hash.
    pub fn derive(
        name: &str,
        timestamp: u64,
        nonce: Digest,
        allocation: &[u8],
        policy: &[u8],
    ) -> Result<Self> {
        validate_name(name)?;
        if timestamp == 0 || timestamp > u64::MAX - 15 || nonce == [0; 32] {
            return Err(Error::Invalid("genesis time/nonce"));
        }
        let (entries, _, _) = decode_allocation(allocation)?;
        validate_policy(policy, entries.len())?;
        Self::derive_validated(name, timestamp, nonce, allocation, policy)
    }

    // Only called after complete G/AP admission. This avoids building the note
    // tree twice during full genesis admission.
    fn derive_validated(
        name: &str,
        timestamp: u64,
        nonce: Digest,
        allocation: &[u8],
        policy: &[u8],
    ) -> Result<Self> {
        let ph = carriage_hash("SilkNode/F01-Parameters/v1", &[&parameter_bytes()]);
        let aph = domain_hash("SilkNode-F01-genesis-audit-policy", &[policy]);
        let mut gd = [0; 244];
        gd[..8].copy_from_slice(b"SNGNF001");
        gd[8] = 1;
        gd[12] = name.len() as u8;
        gd[13..13 + name.len()].copy_from_slice(name.as_bytes());
        gd[76..84].copy_from_slice(&timestamp.to_le_bytes());
        gd[84..116].copy_from_slice(&nonce);
        gd[116..148].copy_from_slice(&raw_hash(allocation));
        gd[148..180].copy_from_slice(&RULES_ID);
        gd[180..212].copy_from_slice(&ph);
        gd[212..244].copy_from_slice(&aph);
        let network = domain_hash(
            "SilkNode-F0-network-id",
            &[&[name.len() as u8], name.as_bytes()],
        );
        let chain = carriage_hash("SilkNode/F01-Chain/v1", &[&gd]);
        let profile = carriage_hash("SilkNode/F01-Profile/v1", &[&chain, &RULES_ID, &ph]);
        let genesis = carriage_hash("SilkNode/F01-GenesisId/v1", &[&gd, &chain, &profile]);
        let activation = carriage_hash(
            "SilkNode/F01-Activation/v1",
            &[&genesis, &profile, &0_u64.to_le_bytes(), &RULES_ID],
        );
        let mut x = [0; 256];
        x[..8].copy_from_slice(b"SNCTX003");
        x[8] = 3;
        for (at, id) in [
            (12, network),
            (44, chain),
            (76, profile),
            (108, genesis),
            (140, activation),
            (172, raw_hash(allocation)),
            (220, RULES_ID),
        ] {
            x[at..at + 32].copy_from_slice(&id);
        }
        x[212..220].copy_from_slice(&[3, 0, 4, 0, 1, 0, 0, 0]);
        Ok(Self {
            descriptor: gd,
            context: Context::decode(&x)?,
        })
    }

    /// Canonical exact receipt body for authority(0), auditor(1), or recipient(2).
    pub fn attestation_body(
        &self,
        allocation: &[u8],
        policy: &[u8],
        role: u8,
        index: u32,
    ) -> Result<[u8; 184]> {
        PreparedAttestations::new(self, allocation, policy)?.body(role, index)
    }
}

impl Genesis {
    /// Admit complete canonical material plus explicit operator acceptance of A_G
    /// and its named custody policy. Independent custodians are an external trust
    /// premise, not something different keys can establish here.
    pub fn admit(
        descriptor: &[u8],
        parameters: &[u8],
        allocation: &[u8],
        policy: &[u8],
        receipt: &[u8],
        operator_accepts_trust_premise: bool,
    ) -> Result<Self> {
        if !operator_accepts_trust_premise {
            return Err(Error::Unavailable("genesis trust policy not accepted"));
        }
        if parameters != parameter_bytes() || descriptor.len() != 244 {
            return Err(Error::Invalid("genesis parameters/descriptor length"));
        }
        if descriptor[..12] != *b"SNGNF001\x01\x00\x00\x00" {
            return Err(Error::Invalid("genesis descriptor version"));
        }
        let n = usize::from(descriptor[12]);
        if !(1..=63).contains(&n) || descriptor[13 + n..76].iter().any(|b| *b != 0) {
            return Err(Error::Invalid("genesis name field"));
        }
        let name = std::str::from_utf8(&descriptor[13..13 + n])
            .map_err(|_| Error::Invalid("genesis name"))?;
        validate_name(name)?;
        let timestamp = u64le(descriptor, 76)?;
        let nonce = field(descriptor, 84)?;
        if timestamp == 0 || timestamp > u64::MAX - 15 || nonce == [0; 32] {
            return Err(Error::Invalid("genesis time/nonce"));
        }
        let (recoveries, total, tree) = decode_allocation(allocation)?;
        validate_policy(policy, recoveries.len())?;
        let derived =
            GenesisDerivation::derive_validated(name, timestamp, nonce, allocation, policy)?;
        if derived.descriptor != descriptor {
            return Err(Error::Invalid("genesis derivation mismatch"));
        }
        if receipt.len() != 16 + 248 * (recoveries.len() + 2)
            || receipt[..12] != *b"SNAGR001\x01\x00\x00\x00"
            || u32le(receipt, 12)? as usize != recoveries.len() + 2
        {
            return Err(Error::Invalid("genesis receipt framing"));
        }
        let prepared = PreparedAttestations::new(&derived, allocation, policy)?;
        for slot in 0..recoveries.len() + 2 {
            let (role, index, key_at) = match slot {
                0 => (0, u32::MAX, 16),
                1 => (1, u32::MAX, 48),
                i => (2, (i - 2) as u32, 80 + 32 * (i - 2)),
            };
            let expected = prepared.body(role, index)?;
            let at = 16 + 248 * slot;
            let body = &receipt[at..at + 184];
            if &body[..8] != b"SNAGA001" || body[10..12] != [0; 2] {
                return Err(Error::Invalid("AUTH_ENCODING"));
            }
            if body[8] != role || body[12..144] != expected[12..144] {
                return Err(Error::Invalid("AUTH_CONTEXT_ROLE"));
            }
            verify_role_signature(
                &policy[key_at..key_at + 32],
                &prefixed_message("SilkNode-F01-A_G-attestation", body),
                &receipt[at + 184..at + 248],
            )?;
            if body != expected {
                return Err(Error::Invalid("AUTH_SEMANTICS"));
            }
        }
        Ok(Self {
            context: derived.context,
            descriptor: derived.descriptor,
            allocation: allocation.to_vec(),
            policy: policy.to_vec(),
            receipt: receipt.to_vec(),
            recoveries,
            total,
            tree,
        })
    }
    /// Static N.
    #[must_use]
    pub fn domain(&self) -> Digest {
        self.context.domain()
    }
    /// Complete verified structural context.
    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }
    /// Parameter commitment PH.
    #[must_use]
    pub fn parameters_id(&self) -> Digest {
        self.descriptor[180..212].try_into().expect("fixed GD")
    }
    /// Positive genesis Unix time.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        u64::from_le_bytes(self.descriptor[76..84].try_into().expect("fixed GD"))
    }
    /// Public declared pool supply; hidden supply additionally assumes A_G.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }
    /// Standard initialized note tree.
    #[must_use]
    pub const fn tree(&self) -> &CommitmentTree {
        &self.tree
    }
    /// Genesis recovery entries in commitment order.
    #[must_use]
    pub fn recoveries(&self) -> &[[u8; RECOVERY_BYTES]] {
        &self.recoveries
    }
    /// Exact durable public genesis components (GD/G/AP/AR); PB is fixed separately.
    #[must_use]
    pub fn material(&self) -> [&[u8]; 4] {
        [
            &self.descriptor,
            &self.allocation,
            &self.policy,
            &self.receipt,
        ]
    }
    /// Bounded local public configuration bundle, not a new consensus object.
    /// This preserves the existing retained-genesis bytes exactly.
    #[must_use]
    pub fn local_bundle(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SNF04GN1");
        for component in std::iter::once(parameter_bytes().as_slice()).chain(self.material()) {
            bytes.extend_from_slice(&(component.len() as u32).to_le_bytes());
            bytes.extend_from_slice(component);
        }
        bytes
    }
    /// Admit complete public configuration against an independently selected N.
    /// A bundle cannot authorize its own context or its external A_G trust premise.
    pub fn admit_local_bundle(
        bytes: &[u8],
        expected_domain: &Digest,
        operator_accepts_ag: bool,
    ) -> Result<Self> {
        if bytes.len() > 8 * 1024 * 1024 || bytes.get(..8) != Some(b"SNF04GN1") {
            return Err(Error::Invalid("local genesis bundle framing"));
        }
        let mut at = 8;
        let mut components = Vec::with_capacity(5);
        for _ in 0..5 {
            let len = u32le(bytes, at)? as usize;
            at += 4;
            let end = at
                .checked_add(len)
                .ok_or(Error::Invalid("local genesis bundle length"))?;
            components.push(
                bytes
                    .get(at..end)
                    .ok_or(Error::Invalid("truncated local genesis bundle"))?,
            );
            at = end;
        }
        if at != bytes.len() {
            return Err(Error::Invalid("local genesis bundle trailing bytes"));
        }
        let g = Self::admit(
            components[1],
            components[0],
            components[2],
            components[3],
            components[4],
            operator_accepts_ag,
        )?;
        if g.domain() != *expected_domain {
            return Err(Error::Invalid("unaccepted genesis domain"));
        }
        Ok(g)
    }
}

fn validate_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    let edge = |v: u8| v.is_ascii_lowercase() || v.is_ascii_digit();
    if !(1..=63).contains(&b.len())
        || !edge(b[0])
        || !edge(b[b.len() - 1])
        || b.iter().any(|v| !edge(*v) && *v != b'-')
    {
        return Err(Error::Invalid("canonical network name"));
    }
    Ok(())
}

fn validate_policy(policy: &[u8], n: usize) -> Result<()> {
    if policy.len() != 80 + 32 * n
        || policy[..12] != *b"SNAGP001\x01\x00\x00\x00"
        || u32le(policy, 12)? as usize != n
    {
        return Err(Error::Invalid("audit policy framing"));
    }
    for i in 0..n + 2 {
        admit_role_key(&policy[16 + 32 * i..48 + 32 * i])?;
    }
    if policy[16..48] == policy[48..80] {
        return Err(Error::Invalid("authority/auditor separation"));
    }
    for i in 0..n {
        if policy[48..80] == policy[80 + 32 * i..112 + 32 * i] {
            return Err(Error::Invalid("auditor/recipient separation"));
        }
    }
    Ok(())
}

fn decode_allocation(bytes: &[u8]) -> Result<(Vec<[u8; RECOVERY_BYTES]>, u64, CommitmentTree)> {
    if bytes.len() < 20 || &bytes[..8] != b"SNGEN002" {
        return Err(Error::Invalid("allocation framing"));
    }
    let total = u64le(bytes, 8)?;
    let count = u32le(bytes, 16)? as usize;
    if !(1..=4096).contains(&count)
        || bytes.len() != 20 + 732 * count
        || total == 0
        || total > MAX_VALUE
    {
        return Err(Error::Invalid("allocation bounds"));
    }
    let mut sum = 0_u64;
    let mut commitments = BTreeSet::new();
    let mut entries = Vec::with_capacity(count);
    let mut tree = CommitmentTree::empty();
    for i in 0..count {
        let at = 20 + 732 * i;
        let value = u64le(bytes, at)?;
        if value == 0 {
            return Err(Error::Invalid("zero genesis allocation"));
        }
        sum = sum
            .checked_add(value)
            .ok_or(Error::Invalid("allocation overflow"))?;
        let entry = field::<RECOVERY_BYTES>(bytes, at + 8)?;
        RecoveryOutput::decode(entry)?;
        let cmu = field::<32>(&entry, 0)?;
        if !commitments.insert(cmu) {
            return Err(Error::Invalid("duplicate genesis commitment"));
        }
        let node = Option::<Node>::from(Node::from_bytes(cmu))
            .ok_or(Error::Invalid("genesis commitment encoding"))?;
        tree.append(node)
            .map_err(|()| Error::Invalid("genesis tree capacity"))?;
        entries.push(entry);
    }
    if sum != total {
        return Err(Error::Invalid("declared allocation sum"));
    }
    Ok((entries, total, tree))
}
