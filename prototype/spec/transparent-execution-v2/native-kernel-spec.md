# Transparent NativeKernel semantic specification, version 2

## 1. Status and scope

This file specifies the no-value transparent control implemented by the
`silk-kernel` transaction and genesis paths. The key words MUST, MUST NOT, and
REJECT refer only to this version-2 control. Version 2 retains the version-1
transaction and hash equations and adds neutral evidence codecs and verified
replay promotion.

This role accepts literal chain/profile execution context. It does not validate
a manifest, compute a module identity, attest compiled code, choose graph
order, authenticate body identifiers, seal checkpoint identities, provide
privacy, or authorize valuable operation.

## 2. Canonical primitives

Unsigned integers are fixed-width little-endian. `Hash32` values are exactly 32
bytes. Booleans are exactly `00` or `01`. Every list begins with a little-endian
`u32` element count. Tagged values begin with one `u8` version. Unknown tags,
truncated input, over-bound lengths, allocation failure, and trailing bytes
REJECT. Set-like collections are strictly lexicographically sorted and unique;
ordered lists retain their supplied order.

All semantic hashes use SHA-256 over this transcript:

```text
"SilkNode-Domain-Hash-v1\0"
|| u32_le(domain_length) || domain
|| u32_le(part_count)
|| for each part: u32_le(part_length) || part
```

## 3. Transparent objects

`NativeNoteV1` encodes, in order:

```text
u8(1), value:u64, owner_tag:Hash32, rho:Hash32,
randomness:Hash32, nullifier_key:Hash32
```

The note commitment is:

```text
H("Silk-Transparent-Note-v1", chain_domain, CanonicalEncode(note))
```

The nullifier is:

```text
H("Silk-Transparent-Nullifier-v1", chain_domain,
  nullifier_key, rho, note_commitment)
```

These public fields are test stand-ins, not secret ownership material.

`RecoveryRecordV1` encodes `u8(1)`, the output commitment, and exactly 128
opaque payload bytes. Its hash is:

```text
H("Silk-Transparent-Recovery-Record-v1",
  chain_domain, CanonicalEncode(record))
```

The role binds the supplied payload to a derived commitment. It does not derive,
encrypt, authenticate, distribute, or prove availability of the payload.

## 4. Transparent genesis materialization

`GenesisAllocationTemplateEntryV1` encodes `u8(1)`, one `NativeNoteV1`, and one
128-byte recovery payload. `GenesisAllocationTemplateV1` encodes `u8(1)` and an
ordered list of at most 4,096 entries.

The exact version, count, entry order, note fields, and payload bytes are input
identity. Before materialization, the canonical template hash MUST equal the
trusted allocation-template hash supplied by execution context. The auxiliary
template hash is:

```text
H("SilkNode-Genesis-Allocation-Template", canonical_template_bytes)
```

For every entry, the role derives the note commitment from the literal
`chain_domain`, creates a recovery record by pairing that commitment with the
literal payload, and accumulates `value` into a checked `u128` genesis-issued
total. Materialized entries are sorted by derived commitment. Duplicate derived
commitments REJECT. Callers cannot supply commitments, recovery bindings,
issued totals, state roots, or checkpoint identifiers as genesis results.

The result is a native-state projection for checkpoint-zero construction. The
Checkpoint role owns the final state digest and checkpoint identifier. This
projection is not the A2a-6 non-PoW `GenesisObject`, which is derived from the
sealed profile and checkpoint-zero result by the separate leaf `silk-genesis`
crate. First-mined-child proof-of-work remains a separate, unresolved contract.

## 5. Transaction and body encoding

`TransparentWitnessV1` encodes `u8(1)`, a complete `NativeNoteV1`, and a
Boolean authorization marker. `TransparentInputV1` encodes `u8(1)`, claimed
commitment, claimed nullifier, and witness. `TransparentOutputV1` encodes
`u8(1)`, claimed commitment, and note opening.

`NativeTransactionV1` encodes, in order:

```text
u8(1)
chain_domain:Hash32
profile_domain:Hash32
anchor:Hash32
public_fee:u64
inputs:list[TransparentInputV1]
outputs:list[TransparentOutputV1]
recovery_hashes:list[Hash32]
recovery_records:list[RecoveryRecordV1]
```

Inputs are limited to 16. Outputs, recovery hashes, and recovery records are
each limited to 16. The safe constructor and decoder enforce those allocation
bounds before hashing.

`OrderedBodyV1` encodes `u8(1)`, a literal `body_id`, and its transaction list.
The outer body order is authoritative input from the ordering layer and MUST
NOT be globally sorted by transaction intent. Transactions inside each body
MUST already be strictly ordered by:

```text
(intent_id, instance_hash, canonical_transaction_bytes)
```

Non-canonical within-body order is a structural call failure. The role neither
repairs it nor proves that `body_id` authenticates the supplied bytes.

## 6. Transaction identities

The effect digest commits `u8(1)`, literal chain/profile values, public fee,
ordered input commitment/nullifier pairs, ordered output commitments, and the
ordered recovery-hash vector. It excludes the anchor, witness openings,
authorization markers, and recovery payload bytes:

```text
effect_digest = H("Silk-Effect", canonical_effect_projection)
intent_id     = H("Silk-Intent", effect_digest)
instance_hash = H("Silk-Instance", intent_id, anchor,
                  CanonicalEncode(transaction))
```

The Boolean-witness control has no signatures, so `intent_id` is derived only
from the effect digest. This is not the production authorization construction.

## 7. Greedy evaluation and precedence

Each body is processed in caller-supplied outer order and each transaction in
its verified within-body order. An intent accepted earlier in the lineage or
current interval receives `kernel.duplicate_intent`.

Otherwise the first applicable rejection wins in this order:

1. empty inputs; input bound; output bound;
2. wrong chain; wrong profile; wrong base checkpoint;
3. duplicate input commitment; duplicate nullifier; duplicate output commitment;
4. prior nullifier; same-interval nullifier; prior commitment;
   same-interval commitment;
5. for each input in serialized order: opening/commitment mismatch,
   nullifier mismatch, absence from the exact base live-note map, base-opening
   mismatch, false authorization marker, checked input-sum overflow;
6. for each output in serialized order: opening/commitment mismatch and checked
   output-sum overflow;
7. checked `outputs + fee` overflow, then exact conservation failure;
8. recovery vector-length mismatch, then per output slot commitment mismatch
   and recovery-hash mismatch;
9. fee-pool overflow.

The stable numeric/text transaction codes are listed in
`native-kernel-parameters.json`.

Inputs are read only from the exact base checkpoint. Outputs accepted in the
current interval cannot be spent until a later checkpoint. A rejected
transaction reserves no nullifier, commitment, recovery record, fee, or intent.
An accepted effect atomically removes its base inputs, inserts all nullifiers,
inserts all output notes and historical commitments, appends recovery records,
adds the public fee to the checked `u128` fee pool, and records the intent.

## 8. Native result

One decision contains zero-based global, body, and transaction positions;
literal `body_id`; derived `intent_id`; derived `instance_hash`; and either
`accepted` or one stable rejection code.

The native result contains the complete decision sequence, accepted effects in
execution order, and the resulting native state projection. The base snapshot
is not mutated. The Checkpoint role validates and seals the projection.

The version-2 evidence wire assigns distinct type-tag/version prefixes:

```text
c0 01  NativeStateProjectionV1
c1 01  OutcomeV1
c2 01  DecisionV1
c3 01  AcceptedEffectV1
c4 01  NativeIntervalResultV1
```

`OutcomeV1` then encodes variant `00` for acceptance or variant `01` followed
by the frozen rejection `u16`. A decision encodes its global position, body ID,
body position, transaction position, intent ID, instance hash, and nested
outcome. An accepted effect encodes body ID then intent ID. A native interval
result encodes at most 4,096 decisions, at most 4,096 accepted effects, and one
native-state projection.

The native-state projection encodes, in order, its strictly sorted unique
live-note map, strictly sorted unique nullifiers, strictly sorted unique
commitment history, ordered recovery history, strictly sorted unique accepted
intents, `native_issued:u128`, and `fee_pool:u128`. The canonical `u32` counts do
not introduce a protocol-lifetime state cap. Before allocating, a decoder MUST
bound each count by the bytes remaining divided by that element's minimum
encoded size. A transport may impose a smaller byte budget as local policy,
but that budget is not canonical meaning.

Canonical decoding creates only an `Unverified` artifact. A native projection
may be checked as detached read-only evidence against an explicit chain domain,
but it cannot be supplied to the checkpoint sealer. A native interval result is
promoted only by deterministic re-execution from a trusted base and the exact
ordered bodies, exact comparison of every field, and return of the recomputed
result. Serialized results never become an effect-injection path.

All 25 rejection-code numbers remain frozen. Codes 6 and 7 are rejected at the
safe constructor/decoder boundary before evaluation. With at most sixteen
`u64` values, code 23 cannot arise from a `u128` value accumulator. In a valid
conserved state, an accepted funded fee cannot make `fee_pool` exceed `u128`, so
code 25 is defensive. The shared corpus MUST classify these four boundary or
defensive codes honestly rather than weaken construction or state invariants.

## 9. Role boundary and capability status

This semantic role reads the supplied canonical order/base checkpoint and
writes the note-commitment, nullifier, recovery-history, accepted-effect, and
native-supply projections listed as review metadata in the parameters file. It
does not write a checkpoint identifier or select canonical graph order.

The Rust implementation combines these steps with checkpoint sealing inside one
façade. Transaction evaluation receives a native-only immutable state view and
stages private typed effects; only the checkpoint materializer applies them. A
combined production entrypoint must bind both NativeKernel and Checkpoint
semantics. Rust visibility narrows source-level authority but is not a process
sandbox or runtime attestation.

## 10. Security boundary

The descriptor-independent vectors and detached cross-language transition
corpus are finite evidence, not proof of completeness. The Python oracle is not
a complete node, profile/order/PoW implementation, independently reproduced
build, or production client. Descriptor equality, source hashes, and artifact
hashes are distinct claims. Nothing in this file provides cryptographic
privacy, secure ownership, data availability, PoW safety, economic safety,
compiler trust, reproducible-build evidence, runtime measurement, or production
readiness.
