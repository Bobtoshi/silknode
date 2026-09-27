//! Exact acyclic control evidence. A valid signature is not timely authorization.
use crate::{
    Digest, Error, Result,
    config::SignedConfig,
    field,
    manifest::{SignedManifest, check_context, check_framing},
    message, u32le, u64le,
};
use silk_f04_node::auth::verify_role_signature;
use silk_sapling_f04::codec::domain_hash;
use zeroize::Zeroize;

/// Fixed signed authorization-fence values, not configurable deadlines.
pub const FENCE: [u64; 4] = [18_500_000_000, 1, 9_500_000_000, 19_750_000_000];

/// Logical signer, not necessarily the immediate forwarding TLS peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Source-side relay.
    A = 0,
    /// Exit relay.
    B = 1,
    /// First fixed producer.
    P0 = 2,
    /// Second fixed producer.
    P1 = 3,
    /// Third fixed producer.
    P2 = 4,
}
/// Scheduled control kind; a caller cannot search signer keys after a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A's sealed input batch assertion.
    AReady = 1,
    /// B's complete staged batch assertion.
    BReady = 2,
    /// Producer's signed possession assertion, NOT a proof of possession.
    Ack = 3,
    /// A's irrevocable terminal authorization.
    Authorize = 4,
    /// B's key-bearing release.
    Release = 5,
    /// Abort evidence in an allowed open phase, never an authorization revocation.
    Cancel = 6,
    /// A's nested manifest proposal.
    ManifestA = 7,
    /// B's nested manifest agreement.
    ManifestB = 8,
}

/// Signature-checked fixed control. It does not attest timely local observation,
/// producer possession, terminal-journal durability or permission to expose data.
pub struct SignedControl {
    bytes: [u8; 512],
    kind: Kind,
    role: Role,
    id: Digest,
}
impl Drop for SignedControl {
    fn drop(&mut self) {
        // RELEASE carries a key. Wipe this owned control buffer as well as the
        // staged-batch key owner; no claim covers upstream copies or remote B.
        self.bytes.zeroize();
    }
}
impl SignedControl {
    /// Check fixed bytes, expected logical kind/role/context, then exact signatures
    /// and local body semantics. Stateful consumers MUST check phase first and
    /// complete this verification before their unchanged observation barrier.
    /// # Errors
    /// Returns framing/context/ED/semantic errors without any state mutation.
    pub fn verify(
        input: &[u8],
        config: &SignedConfig,
        round: u64,
        kind: Kind,
        role: Role,
    ) -> Result<Self> {
        let bytes: [u8; 512] = input
            .try_into()
            .map_err(|_| Error::Invalid("AUTH_ENCODING"))?;
        if &bytes[..8] != b"SNCTLF03"
            || !(1..=8).contains(&bytes[8])
            || bytes[9] > 4
            || bytes[11] != 0
        {
            return Err(Error::Invalid("AUTH_ENCODING"));
        }
        // Framing uses the encoded type, not an expected type under which the
        // same bytes might be interpreted as a different variant.
        let nested = bytes[8] >= 7;
        if nested {
            if bytes[280..448] != [0; 168] {
                return Err(Error::Invalid("AUTH_ENCODING"));
            }
            check_framing(&bytes[88..216])?;
        } else {
            if bytes[248] > 32
                || bytes[249..256] != [0; 7]
                || (bytes[8] != 5 && bytes[288..320] != [0; 32])
                || (!matches!(bytes[8], 4 | 5) && bytes[416..448] != [0; 32])
            {
                return Err(Error::Invalid("AUTH_ENCODING"));
            }
            let unused = match bytes[8] {
                1 => bytes[152..248] != [0; 96] || bytes[256..448] != [0; 192],
                2 => bytes[216..248] != [0; 32] || bytes[288..448] != [0; 160],
                3 => bytes[288..448] != [0; 160],
                6 => bytes[120..448] != [0; 328],
                _ => false,
            };
            if unused {
                return Err(Error::Invalid("AUTH_ENCODING"));
            }
        }
        let role_allowed = match kind {
            Kind::AReady | Kind::Authorize | Kind::ManifestA => role == Role::A,
            Kind::BReady | Kind::Release | Kind::ManifestB => role == Role::B,
            Kind::Ack => matches!(role, Role::P0 | Role::P1 | Role::P2),
            Kind::Cancel => true, // Channel/phase admission remains mandatory outside this codec.
        };
        if bytes[8] != kind as u8
            || bytes[9] != role as u8
            || !role_allowed
            || bytes[12..44] != config.domain()
            || bytes[44..76] != config.id()
            || u32le(&bytes, 76)? != config.cohort()
            || u64le(&bytes, 80)? != round
            || !config.contains_round(round)
        {
            return Err(Error::Invalid("AUTH_CONTEXT_ROLE"));
        }
        let key = config.endpoints()[role as usize].signing;
        verify_role_signature(
            &key,
            &message("SilkNode-F0-control", &[&bytes[..448]]),
            &bytes[448..],
        )?;
        if nested {
            // Deliberately verify both signatures before nested body semantics.
            verify_role_signature(
                &key,
                &message("SilkNode-F0-round", &[&config.id(), &bytes[88..216]]),
                &bytes[216..280],
            )?;
            check_context(&bytes[88..216], config, round)
                .map_err(|_| Error::Invalid("AUTH_SEMANTICS"))?;
        }
        if bytes[10] > 1
            || (kind == Kind::Cancel && bytes[10] != 0)
            || (matches!(kind, Kind::Authorize | Kind::Release) && bytes[10] != 1)
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        if matches!(kind, Kind::Authorize | Kind::Release) {
            for (slot, value) in FENCE.iter().enumerate() {
                if u64le(&bytes, 416 + 8 * slot)? != *value {
                    return Err(Error::Invalid("AUTH_SEMANTICS"));
                }
            }
        }
        Ok(Self {
            id: domain_hash("SilkNode-F0-control-id", &[&bytes]),
            bytes,
            kind,
            role,
        })
    }
    /// Complete unchanged512-byte signed control.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 512] {
        &self.bytes
    }
    /// Hash of complete control, including signature bytes.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Exact authenticated control variant.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Exact expected logical signer.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
}

/// Complete cryptographic reference-chain evidence, not a timely release decision.
pub struct AuthorizationEvidence<'a> {
    authorization: &'a SignedControl,
}

/// Exact unsigned A terminal body derived from the complete readiness chain.
///
/// Persistence must precede signing, and the caller must separately close its
/// observation barrier. This projection alone is not permission to authorize.
pub struct PreparedAuthorization {
    body: [u8; 448],
}

/// Matching cryptographic readiness pair, not timely possession or proof checks.
pub struct ReadyPairEvidence<'a> {
    a: &'a SignedControl,
    b: &'a SignedControl,
}
impl ReadyPairEvidence<'_> {
    /// Exact A readiness control.
    #[must_use]
    pub const fn a(&self) -> &SignedControl {
        self.a
    }
    /// Exact B readiness control.
    #[must_use]
    pub const fn b(&self) -> &SignedControl {
        self.b
    }
}
/// Match the full signed A/B readiness pair before collecting producer ACKs.
/// # Errors
/// Refuses wrong role/kind/status/context/manifest/count/batch reference.
pub fn check_ready_pair<'a>(
    manifest: &SignedManifest,
    a: &'a SignedControl,
    b: &'a SignedControl,
) -> Result<ReadyPairEvidence<'a>> {
    if a.kind != Kind::AReady
        || b.kind != Kind::BReady
        || a.bytes[248] < 8
        || b.bytes[184..216] != a.id
    {
        return Err(Error::Invalid("AUTH_SEMANTICS"));
    }
    for control in [a, b] {
        if control.bytes[10] != 1
            || control.bytes[12..44] != manifest.domain()
            || control.bytes[44..76] != manifest.config()
            || control.bytes[76..80] != manifest.bytes()[40..44]
            || u64le(&control.bytes, 80)? != manifest.round()
            || control.bytes[88..120] != manifest.id()
            || control.bytes[120..152] != a.bytes[120..152]
            || control.bytes[248] != a.bytes[248]
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
    }
    Ok(ReadyPairEvidence { a, b })
}
impl PreparedAuthorization {
    /// Nonsecret exact unsigned terminal body, including the fixed fence.
    #[must_use]
    pub const fn body(&self) -> &[u8; 448] {
        &self.body
    }
    pub(crate) fn check<'a>(
        &self,
        authorization: &'a SignedControl,
    ) -> Result<AuthorizationEvidence<'a>> {
        if authorization.kind != Kind::Authorize || authorization.bytes[..448] != self.body {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
        Ok(AuthorizationEvidence { authorization })
    }
}
impl AuthorizationEvidence<'_> {
    /// Exact A control whose complete manifest/readiness/ACK chain was checked.
    #[must_use]
    pub const fn control(&self) -> &SignedControl {
        self.authorization
    }
}

/// Verify the complete acyclic chain against the exact co-signed manifest.
///
/// Does not establish timely receipt, honest ACK possession,
/// independent operators, clock health, batch availability or durable decisions.
/// # Errors
/// Refuses any absent/wrong-role/reference/context/batch/count/fence mismatch.
pub fn check_authorization<'a>(
    manifest: &SignedManifest,
    a: &SignedControl,
    b: &SignedControl,
    acks: [&SignedControl; 3],
    authorization: &'a SignedControl,
) -> Result<AuthorizationEvidence<'a>> {
    let expected = prepare_authorization(manifest, a, b, acks)?;
    expected.check(authorization)
}

/// Check readiness/ACK references before A's persist-then-sign terminal decision.
/// # Errors
/// Refuses incomplete or inconsistent signed evidence. Does not verify timing.
pub fn prepare_authorization(
    manifest: &SignedManifest,
    a: &SignedControl,
    b: &SignedControl,
    acks: [&SignedControl; 3],
) -> Result<PreparedAuthorization> {
    check_ready_pair(manifest, a, b)?;
    for control in acks {
        if control.bytes[10] != 1
            || control.bytes[12..44] != manifest.domain()
            || control.bytes[44..76] != manifest.config()
            || control.bytes[76..80] != manifest.bytes()[40..44]
            || u64le(&control.bytes, 80)? != manifest.round()
            || control.bytes[88..120] != manifest.id()
            || control.bytes[120..152] != a.bytes[120..152]
            || control.bytes[248] != a.bytes[248]
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
    }
    for (slot, ack) in acks.iter().enumerate() {
        if ack.kind != Kind::Ack || ack.role as usize != slot + 2 {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
    }
    for control in acks {
        if control.bytes[152..184] != b.bytes[152..184]
            || control.bytes[184..216] != a.id
            || control.bytes[216..248] != b.id
            || control.bytes[256..288] != b.bytes[256..288]
        {
            return Err(Error::Invalid("AUTH_SEMANTICS"));
        }
    }
    let mut body: [u8; 448] = acks[0].bytes[..448]
        .try_into()
        .map_err(|_| Error::Invalid("AUTH_ENCODING"))?;
    body[8] = Kind::Authorize as u8;
    body[9] = Role::A as u8;
    for (slot, ack) in acks.iter().enumerate() {
        body[320 + slot * 32..352 + slot * 32].copy_from_slice(&ack.id);
    }
    for (slot, value) in FENCE.iter().enumerate() {
        body[416 + slot * 8..424 + slot * 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(PreparedAuthorization { body })
}

/// Match B's key-bearing control to a previously fully checked authorization.
///
/// Caller MUST verify full staged batch and enforce release phase before exposure.
/// # Errors
/// Refuses altered signed shared fields, wrong type or a key-commitment mismatch.
pub fn check_release<'a>(
    evidence: &AuthorizationEvidence<'_>,
    release: &'a SignedControl,
) -> Result<ReleaseEvidence<'a>> {
    let authorization = evidence.authorization;
    if authorization.kind != Kind::Authorize
        || release.kind != Kind::Release
        || authorization.bytes[10..288] != release.bytes[10..288]
        || authorization.bytes[320..448] != release.bytes[320..448]
    {
        return Err(Error::Invalid("AUTH_SEMANTICS"));
    }
    if domain_hash(
        "SilkNode-F0-release-key",
        &[
            &field::<32>(&release.bytes, 44)?,
            &release.bytes[88..120],
            &release.bytes[288..320],
        ],
    ) != field::<32>(&release.bytes, 256)?
    {
        return Err(Error::Invalid("AUTH_SEMANTICS"));
    }
    Ok(ReleaseEvidence { release })
}

/// Complete cryptographic release references/key commitment, NOT schedule,
/// durable-decision or complete-staged-batch evidence.
pub struct ReleaseEvidence<'a> {
    release: &'a SignedControl,
}
impl ReleaseEvidence<'_> {
    /// Exact B control checked against the complete A reference chain.
    #[must_use]
    pub const fn control(&self) -> &SignedControl {
        self.release
    }
}
