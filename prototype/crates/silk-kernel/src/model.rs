//! Canonical transparent transaction and note data.

use silk_types::{
    BodyCommitment, CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError,
    Decoder, DomainHashError, EffectDigest, EncodeError, Encoder, GenesisAllocationTemplateHash,
    Hash32, IntentId, NoteCommitment, Nullifier, ProfileDomain, VertexId,
    derive_genesis_allocation_template_hash, domain_hash, hash_domains,
};
use thiserror::Error;

use crate::{MAX_GENESIS_ALLOCATIONS, MAX_INPUTS, MAX_OUTPUTS, RECOVERY_PAYLOAD_BYTES};

const NOTE_VERSION: u8 = 1;
const WITNESS_VERSION: u8 = 1;
const INPUT_VERSION: u8 = 1;
const OUTPUT_VERSION: u8 = 1;
const RECOVERY_VERSION: u8 = 1;
const TRANSACTION_VERSION: u8 = 1;
const ORDERED_BODY_VERSION: u8 = 1;
const GENESIS_ALLOCATION_TEMPLATE_ENTRY_VERSION: u8 = 1;
const GENESIS_ALLOCATION_TEMPLATE_VERSION: u8 = 1;

const HASH_BYTES: usize = 32;
const NATIVE_NOTE_MIN_BYTES: usize = 1 + 8 + (4 * HASH_BYTES);
const TRANSPARENT_WITNESS_MIN_BYTES: usize = 1 + NATIVE_NOTE_MIN_BYTES + 1;
const TRANSPARENT_INPUT_MIN_BYTES: usize = 1 + (2 * HASH_BYTES) + TRANSPARENT_WITNESS_MIN_BYTES;
const TRANSPARENT_OUTPUT_MIN_BYTES: usize = 1 + HASH_BYTES + NATIVE_NOTE_MIN_BYTES;
const RECOVERY_RECORD_MIN_BYTES: usize = 1 + HASH_BYTES + RECOVERY_PAYLOAD_BYTES;
const NATIVE_TRANSACTION_MIN_BYTES: usize = 1 + (3 * HASH_BYTES) + 8 + (4 * 4);
const GENESIS_ALLOCATION_ENTRY_MIN_BYTES: usize =
    1 + NATIVE_NOTE_MIN_BYTES + RECOVERY_PAYLOAD_BYTES;

const NOTE_DOMAIN: &[u8] = b"Silk-Transparent-Note-v1";
const NULLIFIER_DOMAIN: &[u8] = b"Silk-Transparent-Nullifier-v1";
const RECOVERY_DOMAIN: &[u8] = b"Silk-Transparent-Recovery-Record-v1";
const ORDERED_BODY_DOMAIN: &[u8] = b"Silk-Transparent-Ordered-Body-v1";

fn decode_remaining_bounded_list<T: CanonicalDecode>(
    decoder: &mut Decoder<'_>,
    semantic_max: usize,
    minimum_item_bytes: usize,
) -> Result<Vec<T>, DecodeError> {
    let remaining_max = decoder.remaining() / minimum_item_bytes;
    let length = decoder.read_len("list", semantic_max)?;
    if length > remaining_max {
        return Err(DecodeError::LimitExceeded {
            kind: "list",
            length,
            max: remaining_max,
        });
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| DecodeError::AllocationFailed {
            kind: "list",
            length,
        })?;
    for _ in 0..length {
        values.push(T::decode(decoder)?);
    }
    Ok(values)
}

/// A transparent opening of one native test-SILK note.
///
/// Every field, including `nullifier_key`, is public in this control model.
/// This is not a private note and possession of these bytes is not ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNote {
    /// Symbolic native amount. No external asset identifier exists in this crate.
    pub value: u64,
    /// Public test recipient label.
    pub owner_tag: Hash32,
    /// Position-independent creating-action value.
    pub rho: Hash32,
    /// Public test commitment randomness.
    pub randomness: Hash32,
    /// Public stand-in for future secret nullifier-deriving key material.
    pub nullifier_key: Hash32,
}

impl NativeNote {
    /// Derives this opening's chain-bound transparent note commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn commitment(&self, chain_domain: ChainDomain) -> Result<NoteCommitment, DomainHashError> {
        let encoded = self.to_canonical_bytes()?;
        domain_hash(NOTE_DOMAIN, &[chain_domain.as_bytes(), &encoded]).map(NoteCommitment::new)
    }

    /// Derives the one chain-bound nullifier fixed by this public opening.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn nullifier(&self, chain_domain: ChainDomain) -> Result<Nullifier, DomainHashError> {
        let commitment = self.commitment(chain_domain)?;
        domain_hash(
            NULLIFIER_DOMAIN,
            &[
                chain_domain.as_bytes(),
                self.nullifier_key.as_bytes(),
                self.rho.as_bytes(),
                commitment.as_bytes(),
            ],
        )
        .map(Nullifier::new)
    }
}

impl CanonicalEncode for NativeNote {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(NOTE_VERSION);
        self.value.encode(encoder)?;
        self.owner_tag.encode(encoder)?;
        self.rho.encode(encoder)?;
        self.randomness.encode(encoder)?;
        self.nullifier_key.encode(encoder)
    }
}

impl CanonicalDecode for NativeNote {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[NOTE_VERSION])?;
        Ok(Self {
            value: u64::decode(decoder)?,
            owner_tag: Hash32::decode(decoder)?,
            rho: Hash32::decode(decoder)?,
            randomness: Hash32::decode(decoder)?,
            nullifier_key: Hash32::decode(decoder)?,
        })
    }
}

/// Public control witness replacing a future membership and ownership proof.
///
/// This witness is deliberately non-cryptographic. `authorization_valid` is a
/// test switch, not a signature, proof, credential, or security boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentWitness {
    /// Fully revealed note opening.
    pub note: NativeNote,
    /// Explicit test-only stand-in for authorization verification.
    pub authorization_valid: bool,
}

impl CanonicalEncode for TransparentWitness {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(WITNESS_VERSION);
        self.note.encode(encoder)?;
        self.authorization_valid.encode(encoder)
    }
}

impl CanonicalDecode for TransparentWitness {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[WITNESS_VERSION])?;
        Ok(Self {
            note: NativeNote::decode(decoder)?,
            authorization_valid: bool::decode(decoder)?,
        })
    }
}

/// One public nullifier paired with its transparent input witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentInput {
    /// Claimed checkpoint note commitment.
    pub commitment: NoteCommitment,
    /// Claimed unique spend nullifier.
    pub nullifier: Nullifier,
    /// Non-cryptographic revealed opening and test authorization marker.
    pub witness: TransparentWitness,
}

impl CanonicalEncode for TransparentInput {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(INPUT_VERSION);
        self.commitment.encode(encoder)?;
        self.nullifier.encode(encoder)?;
        self.witness.encode(encoder)
    }
}

impl CanonicalDecode for TransparentInput {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[INPUT_VERSION])?;
        Ok(Self {
            commitment: NoteCommitment::decode(decoder)?,
            nullifier: Nullifier::decode(decoder)?,
            witness: TransparentWitness::decode(decoder)?,
        })
    }
}

/// One claimed output commitment and its revealed control-model opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparentOutput {
    /// Claimed new note commitment.
    pub commitment: NoteCommitment,
    /// Fully revealed output opening.
    pub note: NativeNote,
}

impl CanonicalEncode for TransparentOutput {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(OUTPUT_VERSION);
        self.commitment.encode(encoder)?;
        self.note.encode(encoder)
    }
}

impl CanonicalDecode for TransparentOutput {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[OUTPUT_VERSION])?;
        Ok(Self {
            commitment: NoteCommitment::decode(decoder)?,
            note: NativeNote::decode(decoder)?,
        })
    }
}

/// A fixed-size public recovery record paired to one output commitment.
///
/// The bytes are opaque test data. This type neither encrypts nor authenticates
/// them; the kernel only requires their exact presence, position, and hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecord {
    /// Output commitment occupying the same transaction slot.
    pub output_commitment: NoteCommitment,
    /// Fixed-size opaque transparent recovery payload.
    pub payload: [u8; RECOVERY_PAYLOAD_BYTES],
}

impl RecoveryRecord {
    /// Derives the chain-bound record hash committed by a transaction effect.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn record_hash(&self, chain_domain: ChainDomain) -> Result<Hash32, DomainHashError> {
        let encoded = self.to_canonical_bytes()?;
        domain_hash(RECOVERY_DOMAIN, &[chain_domain.as_bytes(), &encoded])
    }
}

impl CanonicalEncode for RecoveryRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(RECOVERY_VERSION);
        self.output_commitment.encode(encoder)?;
        encoder.write_fixed(&self.payload);
        Ok(())
    }
}

impl CanonicalDecode for RecoveryRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[RECOVERY_VERSION])?;
        Ok(Self {
            output_commitment: NoteCommitment::decode(decoder)?,
            payload: decoder.read_fixed()?,
        })
    }
}

/// One checkpoint-anchored native transaction in the transparent control model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransaction {
    /// Immutable network identity.
    pub chain_domain: ChainDomain,
    /// Active protocol-rule profile identity.
    pub profile_domain: ProfileDomain,
    /// Exact materialized checkpoint against which every input is proven.
    pub anchor: CheckpointId,
    /// Public native fee moved into the checkpoint fee pool.
    pub public_fee: u64,
    /// Transparent input statements and witnesses.
    pub(crate) inputs: Vec<TransparentInput>,
    /// Transparent output statements and openings.
    pub(crate) outputs: Vec<TransparentOutput>,
    /// Slot-ordered hashes committed by the public effect.
    pub(crate) recovery_hashes: Vec<Hash32>,
    /// Slot-ordered fixed-size records required before acceptance.
    pub(crate) recovery_records: Vec<RecoveryRecord>,
}

/// A local construction attempt exceeded a canonical transaction resource bound.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{field} length {actual} exceeds limit {max}")]
pub struct TransactionBoundError {
    /// Name of the bounded transaction vector.
    pub field: &'static str,
    /// Supplied element count.
    pub actual: usize,
    /// Maximum accepted element count.
    pub max: usize,
}

impl NativeTransaction {
    /// Constructs a transaction only after enforcing every vector allocation bound.
    ///
    /// Semantic inconsistencies remain representable so the interpreter can
    /// return deterministic rejection codes, but no safe public constructor or
    /// decoder can create an oversized vector that is later hashed.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBoundError`] when any input/output/recovery vector
    /// exceeds its explicit limit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_domain: ChainDomain,
        profile_domain: ProfileDomain,
        anchor: CheckpointId,
        public_fee: u64,
        inputs: Vec<TransparentInput>,
        outputs: Vec<TransparentOutput>,
        recovery_hashes: Vec<Hash32>,
        recovery_records: Vec<RecoveryRecord>,
    ) -> Result<Self, TransactionBoundError> {
        check_bound("inputs", inputs.len(), MAX_INPUTS)?;
        check_bound("outputs", outputs.len(), MAX_OUTPUTS)?;
        check_bound("recovery hashes", recovery_hashes.len(), MAX_OUTPUTS)?;
        check_bound("recovery records", recovery_records.len(), MAX_OUTPUTS)?;
        Ok(Self {
            chain_domain,
            profile_domain,
            anchor,
            public_fee,
            inputs,
            outputs,
            recovery_hashes,
            recovery_records,
        })
    }

    /// Returns the bounded transparent input vector.
    #[must_use]
    pub fn inputs(&self) -> &[TransparentInput] {
        &self.inputs
    }

    /// Returns the bounded transparent output vector.
    #[must_use]
    pub fn outputs(&self) -> &[TransparentOutput] {
        &self.outputs
    }

    /// Returns declared recovery hashes in output-slot order.
    #[must_use]
    pub fn recovery_hashes(&self) -> &[Hash32] {
        &self.recovery_hashes
    }

    /// Returns fixed-size recovery records in output-slot order.
    #[must_use]
    pub fn recovery_records(&self) -> &[RecoveryRecord] {
        &self.recovery_records
    }

    /// Computes the anchor-independent public effect digest.
    ///
    /// Witness openings, authorization markers, recovery bytes, and the anchor
    /// are deliberately excluded. Their public claims or hashes remain bound.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn effect_digest(&self) -> Result<EffectDigest, DomainHashError> {
        let mut encoder = Encoder::new();
        encoder.write_u8(1);
        self.chain_domain.encode(&mut encoder)?;
        self.profile_domain.encode(&mut encoder)?;
        self.public_fee.encode(&mut encoder)?;
        encoder.write_len("effect inputs", self.inputs.len())?;
        for input in &self.inputs {
            input.commitment.encode(&mut encoder)?;
            input.nullifier.encode(&mut encoder)?;
        }
        encoder.write_len("effect outputs", self.outputs.len())?;
        for output in &self.outputs {
            output.commitment.encode(&mut encoder)?;
        }
        encoder.write_list(&self.recovery_hashes)?;
        domain_hash(hash_domains::EFFECT, &[encoder.as_slice()]).map(EffectDigest::new)
    }

    /// Computes the canonical conflict-order identifier for this transparent effect.
    ///
    /// The production design additionally binds real spend-authorization
    /// signatures. This non-cryptographic profile has no signatures, so the
    /// effect digest uniquely determines its intent.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn intent_id(&self) -> Result<IntentId, DomainHashError> {
        let effect = self.effect_digest()?;
        domain_hash(hash_domains::INTENT, &[effect.as_bytes()]).map(IntentId::new)
    }

    /// Computes an anchor-and-witness-specific tie-break identifier.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn instance_hash(&self) -> Result<Hash32, DomainHashError> {
        let intent = self.intent_id()?;
        let bytes = self.to_canonical_bytes()?;
        domain_hash(
            hash_domains::INSTANCE,
            &[intent.as_bytes(), self.anchor.as_bytes(), &bytes],
        )
    }
}

const fn check_bound(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), TransactionBoundError> {
    if actual > max {
        Err(TransactionBoundError { field, actual, max })
    } else {
        Ok(())
    }
}

impl CanonicalEncode for NativeTransaction {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(TRANSACTION_VERSION);
        self.chain_domain.encode(encoder)?;
        self.profile_domain.encode(encoder)?;
        self.anchor.encode(encoder)?;
        self.public_fee.encode(encoder)?;
        encoder.write_list(&self.inputs)?;
        encoder.write_list(&self.outputs)?;
        encoder.write_list(&self.recovery_hashes)?;
        encoder.write_list(&self.recovery_records)
    }
}

impl CanonicalDecode for NativeTransaction {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[TRANSACTION_VERSION])?;
        Ok(Self {
            chain_domain: ChainDomain::decode(decoder)?,
            profile_domain: ProfileDomain::decode(decoder)?,
            anchor: CheckpointId::decode(decoder)?,
            public_fee: u64::decode(decoder)?,
            inputs: decode_remaining_bounded_list(
                decoder,
                MAX_INPUTS,
                TRANSPARENT_INPUT_MIN_BYTES,
            )?,
            outputs: decode_remaining_bounded_list(
                decoder,
                MAX_OUTPUTS,
                TRANSPARENT_OUTPUT_MIN_BYTES,
            )?,
            recovery_hashes: decode_remaining_bounded_list(decoder, MAX_OUTPUTS, HASH_BYTES)?,
            recovery_records: decode_remaining_bounded_list(
                decoder,
                MAX_OUTPUTS,
                RECOVERY_RECORD_MIN_BYTES,
            )?,
        })
    }
}

/// One fully available body in an order already selected by the ordering layer.
///
/// This is the kernel's narrow boundary with consensus ordering. It contains no
/// parent, work, or graph logic. The outer slice order passed to
/// [`crate::TransparentExecutionHost::apply_and_seal`] is authoritative; only
/// transactions within each
/// body must already use canonical intent/instance/byte order; the kernel
/// verifies and never silently repairs malformed serialized order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedBody {
    /// Content identifier verified by the ordering/full-data layer.
    pub body_id: VertexId,
    /// Fully available native transactions carried by the body.
    pub transactions: Vec<NativeTransaction>,
}

impl OrderedBody {
    /// Commits the active chain/profile and every canonical transaction byte.
    ///
    /// This execution binding makes rejected as well as accepted body bytes
    /// checkpoint-visible. It does not prove that `body_id` is a valid `PoW`
    /// vertex identifier; the full-data ordering layer must still verify that
    /// header/body relationship before constructing a checkpoint interval.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn execution_binding(
        &self,
        chain_domain: ChainDomain,
        profile_domain: ProfileDomain,
    ) -> Result<BodyCommitment, DomainHashError> {
        let mut encoder = Encoder::new();
        encoder.write_u8(ORDERED_BODY_VERSION);
        encoder.write_list(&self.transactions)?;
        domain_hash(
            ORDERED_BODY_DOMAIN,
            &[
                chain_domain.as_bytes(),
                profile_domain.as_bytes(),
                encoder.as_slice(),
            ],
        )
        .map(BodyCommitment::new)
    }
}

impl CanonicalEncode for OrderedBody {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(ORDERED_BODY_VERSION);
        self.body_id.encode(encoder)?;
        encoder.write_list(&self.transactions)
    }
}

impl CanonicalDecode for OrderedBody {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[ORDERED_BODY_VERSION])?;
        Ok(Self {
            body_id: VertexId::decode(decoder)?,
            transactions: decode_remaining_bounded_list(
                decoder,
                crate::MAX_TRANSACTIONS,
                NATIVE_TRANSACTION_MIN_BYTES,
            )?,
        })
    }
}

/// One chain-independent entry in the no-value transparent allocation template.
///
/// The note opening and fixed recovery payload are literal template data. The
/// chain-bound note commitment and recovery-record binding are deliberately
/// absent and are derived only after the template's chain identity is known.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisAllocationTemplateEntry {
    note: NativeNote,
    recovery_payload: [u8; RECOVERY_PAYLOAD_BYTES],
}

impl GenesisAllocationTemplateEntry {
    /// Constructs one transparent, chain-independent template entry.
    #[must_use]
    pub const fn new(note: NativeNote, recovery_payload: [u8; RECOVERY_PAYLOAD_BYTES]) -> Self {
        Self {
            note,
            recovery_payload,
        }
    }

    /// Returns the complete transparent note opening committed by this entry.
    #[must_use]
    pub const fn note(&self) -> &NativeNote {
        &self.note
    }

    /// Returns the exact fixed-size recovery payload committed by this entry.
    #[must_use]
    pub const fn recovery_payload(&self) -> &[u8; RECOVERY_PAYLOAD_BYTES] {
        &self.recovery_payload
    }

    pub(crate) const fn into_parts(self) -> (NativeNote, [u8; RECOVERY_PAYLOAD_BYTES]) {
        (self.note, self.recovery_payload)
    }
}

impl CanonicalEncode for GenesisAllocationTemplateEntry {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(GENESIS_ALLOCATION_TEMPLATE_ENTRY_VERSION);
        self.note.encode(encoder)?;
        encoder.write_fixed(&self.recovery_payload);
        Ok(())
    }
}

impl CanonicalDecode for GenesisAllocationTemplateEntry {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[GENESIS_ALLOCATION_TEMPLATE_ENTRY_VERSION])?;
        Ok(Self {
            note: NativeNote::decode(decoder)?,
            recovery_payload: decoder.read_fixed()?,
        })
    }
}

/// A versioned, bounded no-value transparent genesis allocation template.
///
/// Entry count, entry order, every transparent note field, and every recovery
/// payload byte are canonical input. No chain-derived commitment, total, root,
/// or state identifier is accepted from the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisAllocationTemplate {
    entries: Vec<GenesisAllocationTemplateEntry>,
}

/// A local template construction attempt exceeded the genesis entry bound.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("genesis allocation template length {actual} exceeds limit {max}")]
pub struct GenesisAllocationTemplateBoundError {
    /// Supplied entry count.
    pub actual: usize,
    /// Maximum accepted entry count.
    pub max: usize,
}

impl GenesisAllocationTemplate {
    /// Constructs a template after enforcing its allocation bound.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisAllocationTemplateBoundError`] before retaining an
    /// entry vector larger than [`MAX_GENESIS_ALLOCATIONS`].
    pub fn new(
        entries: Vec<GenesisAllocationTemplateEntry>,
    ) -> Result<Self, GenesisAllocationTemplateBoundError> {
        if entries.len() > MAX_GENESIS_ALLOCATIONS {
            return Err(GenesisAllocationTemplateBoundError {
                actual: entries.len(),
                max: MAX_GENESIS_ALLOCATIONS,
            });
        }
        Ok(Self { entries })
    }

    /// Returns entries in their exact committed template order.
    #[must_use]
    pub fn entries(&self) -> &[GenesisAllocationTemplateEntry] {
        &self.entries
    }

    /// Derives the typed hash of this exact canonical in-memory template.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or framed hashing error.
    pub fn template_hash(&self) -> Result<GenesisAllocationTemplateHash, DomainHashError> {
        let bytes = self.to_canonical_bytes()?;
        derive_genesis_allocation_template_hash(&bytes)
    }

    pub(crate) fn into_entries(self) -> Vec<GenesisAllocationTemplateEntry> {
        self.entries
    }
}

impl CanonicalEncode for GenesisAllocationTemplate {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(GENESIS_ALLOCATION_TEMPLATE_VERSION);
        encoder.write_list(&self.entries)
    }
}

impl CanonicalDecode for GenesisAllocationTemplate {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(&[GENESIS_ALLOCATION_TEMPLATE_VERSION])?;
        Ok(Self {
            entries: decode_remaining_bounded_list(
                decoder,
                MAX_GENESIS_ALLOCATIONS,
                GENESIS_ALLOCATION_ENTRY_MIN_BYTES,
            )?,
        })
    }
}
