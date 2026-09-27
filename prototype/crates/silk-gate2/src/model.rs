//! Frozen Gate 2 wire model.

#![allow(missing_docs)]

use core::ops::{Deref, DerefMut};

use crate::{
    CanonicalDecode, CanonicalEncode, Decoder, Encoder, Error, MAX_ACCEPTED_HISTORY,
    MAX_ACTIVE_SUITES, MAX_APPLICATION_ROOTS, MAX_BODIES, MAX_BODY_HISTORY, MAX_INPUTS,
    MAX_INTERVAL_EFFECTS, MAX_ISSUANCE_EVENTS, MAX_LEGACY_EXITS, MAX_LIVE_NOTES,
    MAX_NATIVE_HISTORY, MAX_OUTPUTS, MAX_PARENTS, MAX_POLICY_CAVEATS, MAX_RECIPIENT_ROOTS,
    MAX_RECOVERY_ITEMS, MAX_RETAINED_SUITES, MAX_REWARD_BANDS, MAX_SCOPE_MEMBERS, MAX_STATE_BYTES,
};

pub type Hash32 = [u8; 32];
pub type Bytes128 = [u8; 128];

/// Conservative minimum canonical size used by allocation guards.
pub trait WireMin {
    const MIN_BYTES: usize;
}

macro_rules! primitive_wire {
    ($ty:ty, $method:ident, $size:expr) => {
        impl CanonicalEncode for $ty {
            fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
                e.$method(*self);
                Ok(())
            }
        }
        impl CanonicalDecode for $ty {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
                d.$method()
            }
        }
        impl WireMin for $ty {
            const MIN_BYTES: usize = $size;
        }
    };
}

primitive_wire!(u8, u8, 1);
primitive_wire!(u16, u16, 2);
primitive_wire!(u32, u32, 4);
primitive_wire!(u64, u64, 8);
primitive_wire!(u128, u128, 16);

impl CanonicalEncode for bool {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        e.boolean(*self);
        Ok(())
    }
}
impl CanonicalDecode for bool {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.boolean()
    }
}
impl WireMin for bool {
    const MIN_BYTES: usize = 1;
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        e.fixed(self);
        Ok(())
    }
}
impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.fixed(N)?
            .try_into()
            .map_err(|_| Error::code("canonical.unexpected_eof"))
    }
}
impl<const N: usize> WireMin for [u8; N] {
    const MIN_BYTES: usize = N;
}

impl<T: CanonicalEncode> CanonicalEncode for Option<T> {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        match self {
            None => e.u8(0),
            Some(value) => {
                e.u8(1);
                value.encode(e)?;
            }
        }
        Ok(())
    }
}
impl<T: CanonicalDecode> CanonicalDecode for Option<T> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        if d.option_tag()? {
            Ok(Some(T::decode(d)?))
        } else {
            Ok(None)
        }
    }
}
impl<T> WireMin for Option<T> {
    const MIN_BYTES: usize = 1;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoundedVec<T, const N: usize>(pub Vec<T>);

impl<T, const N: usize> BoundedVec<T, N> {
    pub fn new(values: Vec<T>) -> Result<Self, Error> {
        if values.len() > N {
            return Err(Error::code("canonical.limit_exceeded"));
        }
        Ok(Self(values))
    }
}
impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T, const N: usize> DerefMut for BoundedVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<T, const N: usize> From<Vec<T>> for BoundedVec<T, N> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}
impl<T: CanonicalEncode, const N: usize> CanonicalEncode for BoundedVec<T, N> {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        if self.len() > N {
            return Err(Error::code("canonical.limit_exceeded"));
        }
        e.count(self.len())?;
        for value in &self.0 {
            value.encode(e)?;
        }
        Ok(())
    }
}
impl<T: CanonicalDecode + WireMin, const N: usize> CanonicalDecode for BoundedVec<T, N> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = d.count(N, T::MIN_BYTES)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::code("canonical.allocation_failed"))?;
        for _ in 0..count {
            values.push(T::decode(d)?);
        }
        Ok(Self(values))
    }
}
impl<T, const N: usize> WireMin for BoundedVec<T, N> {
    const MIN_BYTES: usize = 4;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SortedUniqueVec<T, const N: usize>(pub Vec<T>);

impl<T, const N: usize> SortedUniqueVec<T, N> {
    pub fn new(values: Vec<T>) -> Self {
        Self(values)
    }
}
impl<T, const N: usize> Deref for SortedUniqueVec<T, N> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T, const N: usize> DerefMut for SortedUniqueVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<T, const N: usize> From<Vec<T>> for SortedUniqueVec<T, N> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}
fn canonical_order<T: CanonicalEncode>(values: &[T]) -> Result<(), Error> {
    let mut previous: Option<Vec<u8>> = None;
    for value in values {
        let bytes = value.canonical_bytes()?;
        if let Some(prior) = previous.as_ref() {
            if bytes == *prior {
                return Err(Error::code("canonical.duplicate_item"));
            }
            if bytes < *prior {
                return Err(Error::code("canonical.unsorted_items"));
            }
        }
        previous = Some(bytes);
    }
    Ok(())
}
impl<T: CanonicalEncode, const N: usize> CanonicalEncode for SortedUniqueVec<T, N> {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        if self.len() > N {
            return Err(Error::code("canonical.limit_exceeded"));
        }
        canonical_order(&self.0)?;
        e.count(self.len())?;
        for value in &self.0 {
            value.encode(e)?;
        }
        Ok(())
    }
}
impl<T: CanonicalDecode + CanonicalEncode + WireMin, const N: usize> CanonicalDecode
    for SortedUniqueVec<T, N>
{
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = d.count(N, T::MIN_BYTES)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::code("canonical.allocation_failed"))?;
        for _ in 0..count {
            values.push(T::decode(d)?);
        }
        canonical_order(&values)?;
        Ok(Self(values))
    }
}
impl<T, const N: usize> WireMin for SortedUniqueVec<T, N> {
    const MIN_BYTES: usize = 4;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SortedUniqueMap<V, const N: usize>(pub Vec<(Hash32, V)>);

impl<V, const N: usize> SortedUniqueMap<V, N> {
    pub fn new(values: Vec<(Hash32, V)>) -> Self {
        Self(values)
    }
    pub fn get(&self, key: &Hash32) -> Option<&V> {
        self.0
            .binary_search_by_key(key, |(candidate, _)| *candidate)
            .ok()
            .map(|index| &self.0[index].1)
    }
}
impl<V, const N: usize> Deref for SortedUniqueMap<V, N> {
    type Target = Vec<(Hash32, V)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<V, const N: usize> DerefMut for SortedUniqueMap<V, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<V: CanonicalEncode, const N: usize> CanonicalEncode for SortedUniqueMap<V, N> {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        if self.len() > N {
            return Err(Error::code("canonical.limit_exceeded"));
        }
        e.count(self.len())?;
        let mut previous: Option<Hash32> = None;
        for (key, value) in &self.0 {
            if let Some(prior) = previous {
                if *key == prior {
                    return Err(Error::code("canonical.duplicate_item"));
                }
                if *key < prior {
                    return Err(Error::code("canonical.unsorted_items"));
                }
            }
            key.encode(e)?;
            value.encode(e)?;
            previous = Some(*key);
        }
        Ok(())
    }
}
impl<V: CanonicalDecode + WireMin, const N: usize> CanonicalDecode for SortedUniqueMap<V, N> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let count = d.count(N, 32 + V::MIN_BYTES)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::code("canonical.allocation_failed"))?;
        let mut previous: Option<Hash32> = None;
        for _ in 0..count {
            let key = Hash32::decode(d)?;
            if let Some(prior) = previous {
                if key == prior {
                    return Err(Error::code("canonical.duplicate_item"));
                }
                if key < prior {
                    return Err(Error::code("canonical.unsorted_items"));
                }
            }
            let value = V::decode(d)?;
            values.push((key, value));
            previous = Some(key);
        }
        Ok(Self(values))
    }
}
impl<V, const N: usize> WireMin for SortedUniqueMap<V, N> {
    const MIN_BYTES: usize = 4;
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident = $tag:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        #[repr(u8)]
        pub enum $name { $($variant = $tag),+ }
        impl CanonicalEncode for $name {
            fn encode(&self, e: &mut Encoder) -> Result<(), Error> { e.u8(*self as u8); Ok(()) }
        }
        impl CanonicalDecode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
                match d.u8()? { $($tag => Ok(Self::$variant),)+ _ => Err(Error::code("canonical.unknown_tag")) }
            }
        }
        impl WireMin for $name { const MIN_BYTES: usize = 1; }
    }
}

wire_enum!(ProfileKind { Genesis = 0, Successor = 1 });
wire_enum!(PolicyLifecyclePhase { CreateAndUse = 0, UseOnly = 1, PrincipalExitOnly = 2 });
wire_enum!(NoteType { Value = 0, Mandate = 1, Reward = 2 });
wire_enum!(AuthorizationRole { Owner = 0, Principal = 1, Delegate = 2 });
wire_enum!(ScopeKind { Recipient = 0, Application = 1 });
wire_enum!(FrequencyMode { SerialWindow = 0, PartitionedTotal = 1 });
wire_enum!(TransferKind {
    Ordinary = 0, MandateCreate = 1, MandateAction = 2, MandateExhaust = 3,
    MandateRevoke = 4, MandateExpireReclaim = 5, SplitDelegate = 6
});
wire_enum!(OutputRole {
    Ordinary = 0, MandateCreate = 1, MandatePayment = 2, MandateSuccessor = 3,
    PrincipalReturn = 4, MigrationDestination = 5, RewardDerived = 6
});
wire_enum!(RecoveryKind { Ordinary = 0, MandateDual = 1, Reward = 2 });
wire_enum!(EnvelopeTag { Transfer = 0, Migration = 1 });
wire_enum!(OutcomeTag { Accepted = 0, Rejected = 1 });
wire_enum!(ParentKind { Body = 0, Fence = 1 });
wire_enum!(BodyNamespaceKind { Unfenced = 0, FenceDirect = 1, FenceDescendant = 2 });
wire_enum!(LegacyTransitionKind { ValueSuiteMigration = 0 });

macro_rules! wire_struct {
    ($name:ident, $version:expr, { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name { $(pub $field: $ty),* }
        impl CanonicalEncode for $name {
            fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
                e.u8($version);
                $(self.$field.encode(e)?;)*
                Ok(())
            }
        }
        impl CanonicalDecode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
                d.version($version)?;
                Ok(Self { $($field: <$ty>::decode(d)?),* })
            }
        }
        impl WireMin for $name { const MIN_BYTES: usize = 1; }
    };
}

wire_struct!(RewardBandV1, 1, { start_position: u128, subsidy: u64 });
wire_struct!(SyntheticRewardScheduleV1, 1, { bands: BoundedVec<RewardBandV1, MAX_REWARD_BANDS> });
wire_struct!(UpgradeScheduleV1, 1, {
    proposal_checkpoint: u64, review_close_checkpoint: u64, exit_open_checkpoint: u64,
    exit_close_checkpoint: u64, activation_checkpoint: u64, overlap_end_checkpoint: u64
});
wire_struct!(ProfileManifestBodyV1, 1, {
    profile_kind: ProfileKind,
    chain_domain: Hash32,
    synthetic_constitution_hash: Hash32,
    protocol_major: u32,
    predecessor_manifest_hash: Hash32,
    predecessor_profile_domain: Hash32,
    upgrade_schedule: Option<UpgradeScheduleV1>,
    activation_checkpoint: u64,
    native_kernel_module_id: Hash32,
    native_kernel_abi: u16,
    checkpoint_module_id: Hash32,
    checkpoint_abi: u16,
    issuance_module_id: Hash32,
    issuance_abi: u16,
    mandate_policy_module_id: Hash32,
    mandate_version: u16,
    policy_lifecycle_phase: PolicyLifecyclePhase,
    active_suite_ids: SortedUniqueVec<Hash32, MAX_ACTIVE_SUITES>,
    retained_migration_source_suite_ids: SortedUniqueVec<Hash32, MAX_RETAINED_SUITES>,
    reward_suite_id: Hash32,
    mandate_suite_id: Hash32,
    synthetic_reward_schedule: SyntheticRewardScheduleV1,
    max_accepted_fees_per_body: u64,
    migration_relation_hash: Hash32,
    state_commitment_migration_hash: Hash32,
    transition_semantics_id: Hash32
});
wire_struct!(TransparentScopeV1, 1, {
    scope_kind: ScopeKind, members: SortedUniqueVec<Hash32, MAX_SCOPE_MEMBERS>
});
wire_struct!(MandateStateV1, 1, {
    policy_module_id: Hash32,
    mandate_version: u16,
    principal_spend_tag: Hash32,
    principal_recovery_tag: Hash32,
    delegate_auth_tag: Hash32,
    per_action_limit: u64,
    expiry_checkpoint: u64,
    recipient_roots: SortedUniqueVec<Hash32, MAX_RECIPIENT_ROOTS>,
    application_roots: SortedUniqueVec<Hash32, MAX_APPLICATION_ROOTS>,
    minimum_interval: u32,
    last_action_anchor: Option<u64>,
    window_size_checkpoints: u32,
    window_index: u64,
    actions_in_window: u32,
    max_actions_per_window: u32,
    remaining_action_tokens: u32,
    frequency_mode: FrequencyMode,
    delegation_depth_left: u8,
    parent_policy_hash: Hash32,
    policy_caveat_hashes: SortedUniqueVec<Hash32, MAX_POLICY_CAVEATS>,
    receipt_disclosure_tag: Hash32
});
wire_struct!(RewardOriginV1, 1, {
    previous_checkpoint: Hash32,
    checkpoint_index: u64,
    body_position: u32,
    body_id: Hash32,
    body_binding: Hash32,
    profile_domain: Hash32,
    reward_suite_id: Hash32,
    issuance_position: u128,
    receiver: Hash32,
    nonce: Hash32,
    subsidy: u64,
    accepted_fees: u64
});
wire_struct!(NativeNoteV2, 2, {
    note_type: NoteType,
    suite_id: Hash32,
    value: u64,
    owner_tag: Hash32,
    rho: Hash32,
    randomness: Hash32,
    nullifier_key: Hash32,
    mandate_state: Option<MandateStateV1>,
    reward_origin: Option<RewardOriginV1>
});
wire_struct!(TransparentWitnessV2, 2, {
    note: NativeNoteV2,
    authorization_role: AuthorizationRole,
    authorization_valid: bool
});
wire_struct!(TransparentInputV2, 2, {
    commitment: Hash32, nullifier: Hash32, witness: TransparentWitnessV2
});
wire_struct!(TransparentOutputV2, 2, {
    output_role: OutputRole, commitment: Hash32, note: NativeNoteV2
});
wire_struct!(RecoveryRecordV2, 2, {
    record_kind: RecoveryKind, output_commitment: Hash32, payload: Bytes128
});
wire_struct!(ActionEvidenceV1, 1, {
    application_tag: Hash32,
    recipient_scope_openings: BoundedVec<TransparentScopeV1, MAX_RECIPIENT_ROOTS>,
    application_scope_openings: BoundedVec<TransparentScopeV1, MAX_APPLICATION_ROOTS>
});
wire_struct!(InputPairV1, 1, { commitment: Hash32, nullifier: Hash32 });
wire_struct!(OutputPairV1, 1, { output_role: OutputRole, commitment: Hash32 });
wire_struct!(TransferEffectProjectionV2, 2, {
    chain_domain: Hash32,
    protocol_manifest_hash: Hash32,
    profile_domain: Hash32,
    policy_phase_root: Hash32,
    suite_id: Hash32,
    anchor_epoch: u64,
    expires_checkpoint: u64,
    public_fee: u64,
    transition_kind: TransferKind,
    action_evidence: Option<ActionEvidenceV1>,
    input_pairs: BoundedVec<InputPairV1, MAX_INPUTS>,
    output_pairs: BoundedVec<OutputPairV1, MAX_OUTPUTS>,
    recovery_hashes: BoundedVec<Hash32, MAX_RECOVERY_ITEMS>
});
wire_struct!(TransferEnvelopeV2, 2, {
    chain_domain: Hash32,
    protocol_manifest_hash: Hash32,
    profile_domain: Hash32,
    policy_phase_root: Hash32,
    suite_id: Hash32,
    anchor: Hash32,
    anchor_epoch: u64,
    expires_checkpoint: u64,
    public_fee: u64,
    transition_kind: TransferKind,
    action_evidence: Option<ActionEvidenceV1>,
    inputs: BoundedVec<TransparentInputV2, MAX_INPUTS>,
    outputs: BoundedVec<TransparentOutputV2, MAX_OUTPUTS>,
    recovery_hashes: BoundedVec<Hash32, MAX_RECOVERY_ITEMS>,
    recovery_records: BoundedVec<RecoveryRecordV2, MAX_RECOVERY_ITEMS>
});
wire_struct!(SyntheticMigrationEnvelopeV1, 1, {
    chain_domain: Hash32,
    protocol_manifest_hash: Hash32,
    profile_domain: Hash32,
    policy_phase_root: Hash32,
    migration_relation_hash: Hash32,
    old_suite_id: Hash32,
    new_suite_id: Hash32,
    execution_anchor: Hash32,
    old_anchor_checkpoint: Hash32,
    old_anchor_root: Hash32,
    expires_checkpoint: u64,
    public_fee: u64,
    inputs: BoundedVec<TransparentInputV2, MAX_INPUTS>,
    outputs: BoundedVec<TransparentOutputV2, MAX_OUTPUTS>,
    recovery_hashes: BoundedVec<Hash32, MAX_RECOVERY_ITEMS>,
    recovery_records: BoundedVec<RecoveryRecordV2, MAX_RECOVERY_ITEMS>,
    value_binding_nonce: Hash32
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusEnvelopeV1 {
    Transfer(TransferEnvelopeV2),
    Migration(SyntheticMigrationEnvelopeV1),
}
impl ConsensusEnvelopeV1 {
    pub const fn tag(&self) -> EnvelopeTag {
        match self {
            Self::Transfer(_) => EnvelopeTag::Transfer,
            Self::Migration(_) => EnvelopeTag::Migration,
        }
    }
}
impl CanonicalEncode for ConsensusEnvelopeV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        crate::canonical::encode_with_byte_cap(e, crate::MAX_ENVELOPE_BYTES, |nested| {
            nested.u8(1);
            self.tag().encode(nested)?;
            match self {
                Self::Transfer(value) => value.encode(nested),
                Self::Migration(value) => value.encode(nested),
            }
        })
    }
}
impl CanonicalDecode for ConsensusEnvelopeV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.within_byte_cap(crate::MAX_ENVELOPE_BYTES, |nested| {
            nested.version(1)?;
            match EnvelopeTag::decode(nested)? {
                EnvelopeTag::Transfer => Ok(Self::Transfer(TransferEnvelopeV2::decode(nested)?)),
                EnvelopeTag::Migration => Ok(Self::Migration(
                    SyntheticMigrationEnvelopeV1::decode(nested)?,
                )),
            }
        })
    }
}
impl WireMin for ConsensusEnvelopeV1 {
    const MIN_BYTES: usize = 3;
}

wire_struct!(ParentRefV1, 1, {
    parent_kind: ParentKind, parent_id: Hash32, profile_domain: Hash32,
    lineage_fence_id: Option<Hash32>
});
wire_struct!(BodyNamespaceV1, 1, {
    namespace_kind: BodyNamespaceKind,
    profile_domain: Hash32,
    active_fence_id: Option<Hash32>,
    parents: SortedUniqueVec<ParentRefV1, MAX_PARENTS>
});
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedBodyV2 {
    pub body_id: Hash32,
    pub namespace: BodyNamespaceV1,
    pub envelopes: BoundedVec<ConsensusEnvelopeV1, { crate::MAX_ENVELOPES }>,
}
impl CanonicalEncode for OrderedBodyV2 {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        crate::canonical::encode_with_byte_cap(e, crate::MAX_BODY_BYTES, |nested| {
            nested.u8(2);
            self.body_id.encode(nested)?;
            self.namespace.encode(nested)?;
            self.envelopes.encode(nested)
        })
    }
}
impl CanonicalDecode for OrderedBodyV2 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.within_byte_cap(crate::MAX_BODY_BYTES, |nested| {
            nested.version(2)?;
            Ok(Self {
                body_id: Hash32::decode(nested)?,
                namespace: BodyNamespaceV1::decode(nested)?,
                envelopes: BoundedVec::decode(nested)?,
            })
        })
    }
}
impl WireMin for OrderedBodyV2 {
    const MIN_BYTES: usize = 1;
}
wire_struct!(EligibilityEntryV1, 1, {
    body_id: Hash32, body_binding: Hash32, reward_suite_id: Hash32,
    receiver: Hash32, nonce: Hash32
});
wire_struct!(LegacyExitDescriptorV1, 1, {
    source_suite_id: Hash32,
    frozen_source_checkpoint: Hash32,
    frozen_source_note_root: Hash32,
    migration_relation_hash: Hash32,
    allowed_transition: LegacyTransitionKind
});
wire_struct!(DerivedRewardV1, 1, {
    note: NativeNoteV2,
    commitment: Hash32,
    recovery_record: RecoveryRecordV2,
    recovery_hash: Hash32
});
wire_struct!(RewardEventBodyV1, 1, {
    body_position: u32,
    body_id: Hash32,
    body_binding: Hash32,
    issuance_position: u128,
    subsidy: u64,
    accepted_fees: u64,
    total_reward: u64,
    derived_reward: Option<DerivedRewardV1>
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeBodyV2 {
    Accepted,
    Rejected(crate::RejectCode),
}
impl CanonicalEncode for OutcomeBodyV2 {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        e.u8(2);
        match self {
            Self::Accepted => e.u8(OutcomeTag::Accepted as u8),
            Self::Rejected(code) => {
                e.u8(OutcomeTag::Rejected as u8);
                e.u16(code.numeric());
            }
        }
        Ok(())
    }
}
impl CanonicalDecode for OutcomeBodyV2 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.version(2)?;
        match OutcomeTag::decode(d)? {
            OutcomeTag::Accepted => Ok(Self::Accepted),
            OutcomeTag::Rejected => Ok(Self::Rejected(crate::RejectCode::try_from(d.u16()?)?)),
        }
    }
}
impl WireMin for OutcomeBodyV2 {
    const MIN_BYTES: usize = 2;
}

wire_struct!(DecisionBodyV2, 2, {
    position: u32,
    body_id: Hash32,
    body_position: u32,
    envelope_position: u32,
    envelope_tag: EnvelopeTag,
    intent_id: Hash32,
    instance_hash: Hash32,
    outcome: OutcomeBodyV2
});
wire_struct!(AcceptedEffectBodyV2, 2, {
    body_id: Hash32,
    envelope_position: u32,
    envelope_tag: EnvelopeTag,
    intent_id: Hash32,
    effect_digest: Hash32,
    output_commitments: BoundedVec<Hash32, MAX_OUTPUTS>,
    output_roles: BoundedVec<OutputRole, MAX_OUTPUTS>
});
wire_struct!(LogicalNativeStateProjectionV2, 2, {
    chain_domain: Hash32,
    live_notes: SortedUniqueMap<NativeNoteV2, MAX_LIVE_NOTES>,
    nullifiers: SortedUniqueVec<Hash32, MAX_NATIVE_HISTORY>,
    commitment_history: BoundedVec<Hash32, MAX_NATIVE_HISTORY>,
    recovery_history: BoundedVec<RecoveryRecordV2, MAX_NATIVE_HISTORY>,
    accepted_intents: SortedUniqueVec<Hash32, MAX_ACCEPTED_HISTORY>,
    accepted_effect_history: BoundedVec<AcceptedEffectBodyV2, MAX_ACCEPTED_HISTORY>,
    issuance_event_history: BoundedVec<RewardEventBodyV1, MAX_ISSUANCE_EVENTS>,
    native_genesis_issued: u128,
    native_issued: u128,
    native_burned: u128,
    issuance_cursor: u128,
    fee_pool: u128,
    security_epoch: u64,
    synthetic_order_carry_hash: Hash32,
    synthetic_daa_carry_hash: Hash32,
    synthetic_pow_key_carry_hash: Hash32
});
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStateV2 {
    pub protocol_manifest_hash: Hash32,
    pub profile_domain: Hash32,
    pub policy_phase_root: Hash32,
    pub active_suite_ids: SortedUniqueVec<Hash32, MAX_ACTIVE_SUITES>,
    pub retained_migration_source_suite_ids: SortedUniqueVec<Hash32, MAX_RETAINED_SUITES>,
    pub reward_suite_id: Hash32,
    pub mandate_suite_id: Hash32,
    pub reward_schedule_hash: Hash32,
    pub legacy_exit_descriptors: SortedUniqueVec<LegacyExitDescriptorV1, MAX_LEGACY_EXITS>,
    pub logical_state: LogicalNativeStateProjectionV2,
}
impl CanonicalEncode for NativeStateV2 {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        crate::canonical::encode_with_byte_cap(e, MAX_STATE_BYTES, |nested| {
            nested.u8(2);
            self.protocol_manifest_hash.encode(nested)?;
            self.profile_domain.encode(nested)?;
            self.policy_phase_root.encode(nested)?;
            self.active_suite_ids.encode(nested)?;
            self.retained_migration_source_suite_ids.encode(nested)?;
            self.reward_suite_id.encode(nested)?;
            self.mandate_suite_id.encode(nested)?;
            self.reward_schedule_hash.encode(nested)?;
            self.legacy_exit_descriptors.encode(nested)?;
            self.logical_state.encode(nested)
        })
    }
}
impl CanonicalDecode for NativeStateV2 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        d.within_byte_cap(MAX_STATE_BYTES, |nested| {
            nested.version(2)?;
            Ok(Self {
                protocol_manifest_hash: Hash32::decode(nested)?,
                profile_domain: Hash32::decode(nested)?,
                policy_phase_root: Hash32::decode(nested)?,
                active_suite_ids: SortedUniqueVec::decode(nested)?,
                retained_migration_source_suite_ids: SortedUniqueVec::decode(nested)?,
                reward_suite_id: Hash32::decode(nested)?,
                mandate_suite_id: Hash32::decode(nested)?,
                reward_schedule_hash: Hash32::decode(nested)?,
                legacy_exit_descriptors: SortedUniqueVec::decode(nested)?,
                logical_state: LogicalNativeStateProjectionV2::decode(nested)?,
            })
        })
    }
}
impl WireMin for NativeStateV2 {
    const MIN_BYTES: usize = 1;
}
wire_struct!(ProfileHandoffBodyV1, 1, {
    chain_domain: Hash32,
    predecessor_manifest_hash: Hash32,
    predecessor_profile_domain: Hash32,
    predecessor_checkpoint: Hash32,
    checkpoint_index: u64,
    note_history_root: Hash32,
    nullifier_root: Hash32,
    cumulative_recovery_root: Hash32,
    accepted_effect_root: Hash32,
    native_genesis_issued: u128,
    native_issued: u128,
    native_burned: u128,
    issuance_cursor: u128,
    security_epoch: u64,
    legacy_anchor_set_hash: Hash32,
    synthetic_order_carry_hash: Hash32,
    synthetic_daa_carry_hash: Hash32,
    synthetic_pow_key_carry_hash: Hash32
});
wire_struct!(TransitionAnchorBodyV1, 1, {
    chain_domain: Hash32,
    predecessor_checkpoint: Hash32,
    checkpoint_index: u64,
    successor_manifest_hash: Hash32,
    transition_semantics_id: Hash32,
    profile_handoff_hash: Hash32,
    state_commitment_migration_hash: Hash32,
    successor_note_history_root: Hash32,
    successor_nullifier_root: Hash32,
    successor_cumulative_recovery_root: Hash32,
    successor_accepted_effect_root: Hash32,
    native_issued: u128,
    native_burned: u128,
    issuance_cursor: u128,
    security_epoch: u64,
    legacy_anchor_set_hash: Hash32
});

macro_rules! top_wire {
    ($name:ident, $tag:expr, $version:expr, $cap:expr, { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name { $(pub $field: $ty),* }
        impl CanonicalEncode for $name {
            fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
                let mut subject = Encoder::new();
                subject.u8($tag);
                subject.u8($version);
                $(self.$field.encode(&mut subject)?;)*
                let bytes = subject.finish();
                crate::canonical::enforce_top_level_byte_cap::<Self>(bytes.len())?;
                e.fixed(&bytes);
                Ok(())
            }
        }
        impl CanonicalDecode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
                if d.u8()? != $tag { return Err(Error::code("canonical.unknown_tag")); }
                d.version($version)?;
                Ok(Self { $($field: <$ty>::decode(d)?),* })
            }
        }
        impl crate::TopLevelWire for $name {
            const TAG: u8 = $tag;
            const VERSION: u8 = $version;
            const BYTE_CAP: usize = $cap;
            fn decode_fields(d: &mut Decoder<'_>) -> Result<Self, Error> {
                Ok(Self { $($field: <$ty>::decode(d)?),* })
            }
        }
        impl WireMin for $name { const MIN_BYTES: usize = 2; }
    };
}

top_wire!(Gate2ProfileV1, 0xc7, 1, { crate::MAX_TOP_LEVEL_BYTES }, {
    manifest_body: ProfileManifestBodyV1,
    reward_schedule_hash: Hash32,
    policy_phase_root: Hash32,
    protocol_manifest_hash: Hash32,
    profile_domain: Hash32
});
top_wire!(SyntheticEligibilityReceiptV1, 0xc8, 1, { crate::MAX_TOP_LEVEL_BYTES }, {
    chain_domain: Hash32,
    protocol_manifest_hash: Hash32,
    profile_domain: Hash32,
    base_checkpoint: Hash32,
    base_issuance_cursor: u128,
    next_checkpoint_index: u64,
    entries: BoundedVec<EligibilityEntryV1, MAX_BODIES>
});
top_wire!(NativeStateProjectionV2, 0xc9, 2, MAX_STATE_BYTES, { state: NativeStateV2 });
top_wire!(OutcomeV2, 0xca, 2, { crate::MAX_TOP_LEVEL_BYTES }, { outcome: OutcomeBodyV2 });
top_wire!(DecisionV2, 0xcb, 2, { crate::MAX_TOP_LEVEL_BYTES }, { decision: DecisionBodyV2 });
top_wire!(AcceptedEffectV2, 0xcc, 2, { crate::MAX_TOP_LEVEL_BYTES }, { effect: AcceptedEffectBodyV2 });
top_wire!(RewardEventV1, 0xcd, 1, { crate::MAX_TOP_LEVEL_BYTES }, { event: RewardEventBodyV1 });
top_wire!(NativeIntervalResultV2, 0xce, 2, MAX_STATE_BYTES, {
    decisions: BoundedVec<DecisionBodyV2, { crate::MAX_ENVELOPES }>,
    accepted_effects: BoundedVec<AcceptedEffectBodyV2, MAX_INTERVAL_EFFECTS>,
    reward_events: BoundedVec<RewardEventBodyV1, MAX_BODIES>,
    resulting_native_state: NativeStateV2
});
top_wire!(CheckpointStateWireV2, 0xcf, 2, MAX_STATE_BYTES, {
    checkpoint_id: Hash32,
    previous_checkpoint: Hash32,
    checkpoint_index: u64,
    native_state: NativeStateV2,
    ordered_body_history: BoundedVec<Hash32, MAX_BODY_HISTORY>,
    bodies_in_checkpoint: BoundedVec<Hash32, MAX_BODIES>,
    body_bindings_in_checkpoint: BoundedVec<Hash32, MAX_BODIES>,
    accepted_effects_in_checkpoint: BoundedVec<AcceptedEffectBodyV2, MAX_INTERVAL_EFFECTS>,
    reward_events_in_checkpoint: BoundedVec<RewardEventBodyV1, MAX_BODIES>,
    active_fence_id: Option<Hash32>
});
top_wire!(TransitionV2, 0xd0, 2, { crate::MAX_TOP_LEVEL_BYTES }, {
    previous: CheckpointStateWireV2,
    next: CheckpointStateWireV2,
    execution_fence_id: Option<Hash32>,
    decisions: BoundedVec<DecisionBodyV2, { crate::MAX_ENVELOPES }>,
    reward_events: BoundedVec<RewardEventBodyV1, MAX_BODIES>
});
top_wire!(ProfileHandoffV1, 0xd1, 1, { crate::MAX_TOP_LEVEL_BYTES }, { handoff: ProfileHandoffBodyV1 });
top_wire!(TransitionAnchorV1, 0xd2, 1, { crate::MAX_TOP_LEVEL_BYTES }, { anchor: TransitionAnchorBodyV1 });
top_wire!(FenceTransitionV1, 0xd3, 1, { crate::MAX_TOP_LEVEL_BYTES }, {
    predecessor: CheckpointStateWireV2,
    successor_profile: Gate2ProfileV1,
    handoff: ProfileHandoffBodyV1,
    transition_anchor: TransitionAnchorBodyV1,
    transition_anchor_id: Hash32,
    fence_id: Hash32
});
top_wire!(OrderedIntervalV1, 0xd4, 1, { crate::MAX_INTERVAL_BYTES }, {
    bodies: BoundedVec<OrderedBodyV2, MAX_BODIES>
});
