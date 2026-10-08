//! IM3-only complete signed chain. Never a legacy authorization conversion.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

/// Strict canonical IM3 control kind; its integer encoding is frozen.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Im3Kind {
    /// A's exact ordered C-input commitment.
    AReady = 1,
    /// C's post-gate output commitment, referring to the complete A control.
    CReady = 2,
    /// B's post-Sapling staged-batch/key commitment.
    BReady = 3,
    /// One exact producer's complete-batch acknowledgement.
    Ack = 4,
    /// A's authorization of all six preceding controls.
    Authorize = 5,
    /// B's irreversible key disclosure, referring to A's authorization.
    Release = 6,
    /// Context-only fixed failure signal, without an index/error code.
    Cancel = 7,
}
/// Strict role encoding, separate from the legacy A/B/producer enum.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Im3Role {
    /// Ingress.
    A = 0,
    /// Independently pinned middle boundary (pinning is not custody proof).
    C = 1,
    /// Exit.
    B = 2,
    /// First producer.
    P0 = 3,
    /// Second producer.
    P1 = 4,
    /// Third producer.
    P2 = 5,
}
impl Im3Role {
    fn key(self, c: &MiddleContext<'_>) -> Digest {
        match self {
            Self::A => c.r2.round.config.endpoints()[0].signing,
            Self::C => c.q.bytes[128..160].try_into().expect("32"),
            Self::B => c.r2.round.config.endpoints()[1].signing,
            Self::P0 => c.r2.round.config.endpoints()[2].signing,
            Self::P1 => c.r2.round.config.endpoints()[3].signing,
            Self::P2 => c.r2.round.config.endpoints()[4].signing,
        }
    }
}
fn binding(c: &MiddleContext<'_>) -> [Digest; 4] {
    [
        c.r2.round.config.id(),
        c.profile.id(),
        c.q.id(),
        c.r2.round.manifest.id(),
    ]
}
/// An exact canonical signature-verified IM3 control. Possession alone grants
/// no socket, payload, durable decision, signing or producer-handoff authority.
pub struct Im3Control {
    bytes: Zeroizing<[u8; 512]>,
    id: Digest,
    binding: [Digest; 4],
    kind: Im3Kind,
    role: Im3Role,
}
impl Im3Control {
    /// Verify all canonical fields, role, context and the genuine strict signature.
    pub fn verify(input: &[u8], c: &MiddleContext<'_>) -> Result<Self> {
        let bytes = Zeroizing::new(
            <[u8; 512]>::try_from(input).map_err(|_| Error::Invalid("IM3 control length"))?,
        );
        let kind = match bytes[8] {
            1 => Im3Kind::AReady,
            2 => Im3Kind::CReady,
            3 => Im3Kind::BReady,
            4 => Im3Kind::Ack,
            5 => Im3Kind::Authorize,
            6 => Im3Kind::Release,
            7 => Im3Kind::Cancel,
            _ => return Err(Error::Invalid("IM3 control kind")),
        };
        let role = match bytes[9] {
            0 => Im3Role::A,
            1 => Im3Role::C,
            2 => Im3Role::B,
            3 => Im3Role::P0,
            4 => Im3Role::P1,
            5 => Im3Role::P2,
            _ => return Err(Error::Invalid("IM3 control role")),
        };
        let permitted = match kind {
            Im3Kind::AReady | Im3Kind::Authorize => role == Im3Role::A,
            Im3Kind::CReady => role == Im3Role::C,
            Im3Kind::BReady | Im3Kind::Release => role == Im3Role::B,
            Im3Kind::Ack => matches!(role, Im3Role::P0 | Im3Role::P1 | Im3Role::P2),
            Im3Kind::Cancel => true,
        };
        // Every optional 32-byte field must be present exactly for its kind.
        // Unpopulated fields are canonical zeros, not ignored extensions.
        let present: [bool; 7] = match kind {
            Im3Kind::AReady => [true, false, false, false, false, false, false],
            Im3Kind::CReady => [true, true, false, true, false, false, false],
            Im3Kind::BReady | Im3Kind::Ack => [true, true, true, true, true, false, false],
            Im3Kind::Authorize => [true, true, true, true, true, false, true],
            Im3Kind::Release => [true; 7],
            Im3Kind::Cancel => [false; 7],
        };
        if !permitted
            || &bytes[..8] != b"SNIM3C01"
            || bytes[10..12] != [0; 2]
            || bytes[12..20] != c.r2.round.manifest.round().to_le_bytes()
            || bytes[20..52] != c.r2.round.config.domain()
            || bytes[52..84] != c.q.id()
            || bytes[84..116] != c.r2.round.manifest.id()
            || bytes[340..344] != (if kind == Im3Kind::Cancel { 0u32 } else { 32u32 }).to_le_bytes()
            || bytes[344..448] != [0; 104]
            || present
                .iter()
                .enumerate()
                .any(|(i, p)| (*p) == (bytes[116 + i * 32..148 + i * 32] == [0; 32]))
            || !crate::aip2_signature(
                &role.key(c),
                &message("SilkNode-IM3-control", &[&bytes[..448]]),
                &bytes[448..],
            )
        {
            return Err(Error::Invalid("IM3 canonical control/signature"));
        }
        Ok(Self {
            id: domain_hash("SilkNode-IM3-control-id", &[bytes.as_slice()]),
            bytes,
            binding: binding(c),
            kind,
            role,
        })
    }
    /// Exact authenticated bytes, for complete-chain forwarding only.
    pub fn bytes(&self) -> &[u8; 512] {
        &self.bytes
    }
    /// Commitment to the complete control, including the signature.
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Authenticated canonical kind.
    pub const fn kind(&self) -> Im3Kind {
        self.kind
    }
    /// Authenticated canonical role.
    pub const fn role(&self) -> Im3Role {
        self.role
    }
    pub(super) fn check(&self, c: &MiddleContext<'_>, kind: Im3Kind) -> Result<()> {
        if self.binding != binding(c)
            || self.kind != kind
            || self.bytes[12..20] != c.r2.round.manifest.round().to_le_bytes()
        {
            return Err(Error::Invalid("IM3 control context/kind"));
        }
        Ok(())
    }
    pub(super) fn field(&self, at: usize) -> Digest {
        self.bytes[at..at + 32].try_into().expect("32")
    }
}
/// Only internal stateful owners may sign. No caller-supplied public READY or
/// authorization constructor can bypass complete gates and durable fences.
pub(super) fn sign(
    c: &MiddleContext<'_>,
    kind: Im3Kind,
    role: Im3Role,
    fields: [Digest; 7],
    key: &SigningKey,
) -> Result<Im3Control> {
    if key.verifying_key().to_bytes() != role.key(c) {
        return Err(Error::Unavailable("IM3 local signing identity"));
    }
    let fields = Zeroizing::new(fields);
    let mut bytes = Zeroizing::new([0; 512]);
    bytes[..8].copy_from_slice(b"SNIM3C01");
    bytes[8] = kind as u8;
    bytes[9] = role as u8;
    bytes[12..20].copy_from_slice(&c.r2.round.manifest.round().to_le_bytes());
    bytes[20..52].copy_from_slice(&c.r2.round.config.domain());
    bytes[52..84].copy_from_slice(&c.q.id());
    bytes[84..116].copy_from_slice(&c.r2.round.manifest.id());
    for (i, value) in fields.iter().enumerate() {
        bytes[116 + i * 32..148 + i * 32].copy_from_slice(value);
    }
    if kind != Im3Kind::Cancel {
        bytes[340..344].copy_from_slice(&32u32.to_le_bytes());
    }
    let signature = key
        .sign(&message("SilkNode-IM3-control", &[&bytes[..448]]))
        .to_bytes();
    bytes[448..].copy_from_slice(&signature);
    Im3Control::verify(bytes.as_slice(), c)
}
/// Full ordered A/C/B readiness evidence, never a substitute aggregate hash.
pub struct Im3ReadyChain {
    pub(super) a: Im3Control,
    pub(super) c: Im3Control,
    pub(super) b: Im3Control,
}
impl Im3ReadyChain {
    /// Consume three signature-verified controls and validate every shared hash
    /// and preceding ID. Actual staged-cell completeness is checked separately.
    pub fn verify(
        context: &MiddleContext<'_>,
        a: Im3Control,
        c: Im3Control,
        b: Im3Control,
    ) -> Result<Self> {
        a.check(context, Im3Kind::AReady)?;
        c.check(context, Im3Kind::CReady)?;
        b.check(context, Im3Kind::BReady)?;
        if c.field(116) != a.field(116)
            || c.field(212) != a.id()
            || b.bytes[116..180] != c.bytes[116..180]
            || b.field(212) != c.id()
        {
            return Err(Error::Invalid("IM3 readiness chain"));
        }
        Ok(Self { a, c, b })
    }
    /// The three complete authenticated controls, in A/C/B order.
    pub fn controls(&self) -> [&[u8; 512]; 3] {
        [self.a.bytes(), self.c.bytes(), self.b.bytes()]
    }
    pub(super) fn check(&self, c: &MiddleContext<'_>) -> Result<()> {
        self.a.check(c, Im3Kind::AReady)?;
        self.c.check(c, Im3Kind::CReady)?;
        self.b.check(c, Im3Kind::BReady)
    }
}
/// Full readiness plus all three distinct producer ACKs, in producer order.
pub struct Im3AckChain {
    pub(super) ready: Im3ReadyChain,
    pub(super) acks: [Im3Control; 3],
    evidence: Digest,
}
impl Im3AckChain {
    /// Authenticate all six complete controls before deriving evidence. Three
    /// copies of one producer's valid ACK do not satisfy this constructor.
    pub fn verify(
        c: &MiddleContext<'_>,
        ready: Im3ReadyChain,
        acks: [Im3Control; 3],
    ) -> Result<Self> {
        ready.check(c)?;
        for (ack, role) in acks.iter().zip([Im3Role::P0, Im3Role::P1, Im3Role::P2]) {
            ack.check(c, Im3Kind::Ack)?;
            if ack.role != role
                || ack.bytes[116..212] != ready.b.bytes[116..212]
                || ack.field(244) != ready.b.field(244)
                || ack.field(212) != ready.b.id()
            {
                return Err(Error::Invalid("IM3 producer ACK chain"));
            }
        }
        let ids = [
            ready.a.id(),
            ready.c.id(),
            ready.b.id(),
            acks[0].id(),
            acks[1].id(),
            acks[2].id(),
        ];
        let q = c.q.id();
        let m = c.r2.round.manifest.id();
        let r = c.r2.round.manifest.round().to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&q, &m, &r];
        parts.extend(ids.iter().map(|id| id.as_slice()));
        let evidence = domain_hash("SilkNode-IM3-evidence", &parts);
        Ok(Self {
            ready,
            acks,
            evidence,
        })
    }
    /// Exact digest of all six ordered controls under Q/M/r.
    pub const fn evidence_digest(&self) -> Digest {
        self.evidence
    }
    /// Complete ACKs for forwarding to every honest authorizer/producer.
    pub fn acknowledgements(&self) -> [&[u8; 512]; 3] {
        [
            self.acks[0].bytes(),
            self.acks[1].bytes(),
            self.acks[2].bytes(),
        ]
    }
    pub(super) fn check(&self, c: &MiddleContext<'_>) -> Result<()> {
        self.ready.check(c)
    }
}
/// A's authenticated authorization, bound to the actual retained six controls.
pub struct Im3Authorization {
    pub(super) chain: Im3AckChain,
    pub(super) control: Im3Control,
}
impl Im3Authorization {
    /// Reject any forged/missing/reordered chain, changed batch or key commitment.
    pub fn verify(c: &MiddleContext<'_>, chain: Im3AckChain, control: Im3Control) -> Result<Self> {
        chain.check(c)?;
        control.check(c, Im3Kind::Authorize)?;
        let b = &chain.ready.b;
        if control.bytes[116..212] != b.bytes[116..212]
            || control.field(244) != b.field(244)
            || control.field(212) != b.id()
            || control.field(308) != chain.evidence
        {
            return Err(Error::Invalid("IM3 authorization chain"));
        }
        Ok(Self { chain, control })
    }
    /// Complete signed A authorization; never permission to disclose a key itself.
    pub fn control(&self) -> &[u8; 512] {
        self.control.bytes()
    }
}
/// Verified release plus its exact full authorization chain. Actual complete
/// producer ciphertext ownership and opening remain a separate private gate.
pub struct Im3Release {
    pub(super) authorization: Im3Authorization,
    pub(super) control: Im3Control,
}
impl Im3Release {
    /// Verify B's exact authorization reference and released-key commitment.
    pub fn verify(
        c: &MiddleContext<'_>,
        authorization: Im3Authorization,
        control: Im3Control,
    ) -> Result<Self> {
        authorization.chain.check(c)?;
        control.check(c, Im3Kind::Release)?;
        let a = &authorization.control;
        if control.bytes[116..212] != a.bytes[116..212]
            || control.field(244) != a.field(244)
            || control.field(212) != a.id()
            || control.field(308) != a.field(308)
            || key_commit(c, &control.field(276)) != control.field(244)
        {
            return Err(Error::Invalid("IM3 release chain/key"));
        }
        Ok(Self {
            authorization,
            control,
        })
    }
    /// Complete signed release control, already public on its original wire.
    pub fn control(&self) -> &[u8; 512] {
        self.control.bytes()
    }
}
pub(super) fn key_commit(c: &MiddleContext<'_>, key: &Digest) -> Digest {
    domain_hash(
        "SilkNode-IM3-key",
        &[
            &c.r2.round.config.id(),
            &c.q.id(),
            &c.r2.round.manifest.id(),
            &c.r2.round.manifest.round().to_le_bytes(),
            key,
        ],
    )
}
