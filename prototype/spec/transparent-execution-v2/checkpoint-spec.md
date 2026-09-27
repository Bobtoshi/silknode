# Transparent Checkpoint semantic specification, version 3

## 1. Status and scope

This file specifies the checkpoint/state-commitment portion currently executed
by `silk-kernel`. The key words MUST, MUST NOT, and REJECT refer only to this
version-3 no-value transparent control. Version 3 retains the version-2 state,
checkpoint hash, and reduced-receipt equations and adds neutral checkpoint and
transition evidence codecs with externally pinned promotion.

The Checkpoint role seals a supplied canonical order and NativeKernel result.
It does not choose graph order, execute transaction validity rules, authenticate
a `body_id` against a PoW object, prove body availability, activate profiles,
or attest compiled code.

## 2. Inputs and role separation

Checkpoint-zero input consists of literal chain/profile execution context and a
NativeKernel genesis projection. Interval input consists of:

- an immutable base `CheckpointState`;
- the authoritative ordered body sequence;
- exact canonical transaction bytes for each body-content binding;
- the NativeKernel decisions, accepted effects, and resulting native state.

The Rust façade computes both role results in one call. The evaluator receives
a read-only native-state view and can stage only typed native effects; the
checkpoint sealer alone materializes them. This source-level boundary remains
in-process and is not a sandbox or independent host.

## 3. Ordered-body content binding

For each body, checkpointing derives:

```text
body_binding = H(
  "Silk-Transparent-Ordered-Body-v1",
  chain_domain,
  profile_domain,
  u8(1) || CanonicalEncode(transaction_list)
)
```

The binding excludes `body_id` deliberately and commits every transaction byte,
including rejected transactions. `body_id` and binding occupy matching positions
in the checkpoint state. Moving the same transaction bytes between bodies or
changing body order changes checkpoint context.

This binding is not proof that `body_id` names those bytes. The ordering and
full-data layer remains responsible for header/body authenticity and
availability before calling the kernel.

## 4. Checkpoint state

`CheckpointStateV1` contains:

```text
chain_domain:Hash32
profile_domain:Hash32
checkpoint_id:Hash32
previous_checkpoint:Hash32
checkpoint_index:u64
live_notes:map[NoteCommitment => NativeNote]
nullifiers:set[Nullifier]
commitment_history:set[NoteCommitment]
recovery_history:list[RecoveryRecord]
ordered_body_history:list[body_id]
bodies_in_checkpoint:list[body_id]
body_bindings_in_checkpoint:list[BodyCommitment]
accepted_intents:set[IntentId]
accepted_effects_in_checkpoint:list[(body_id, intent_id)]
native_issued:u128
fee_pool:u128
```

Map/set encodings are strictly lexicographically ordered by their 32-byte key.
History/effect lists retain consensus order. The state is immutable to callers;
a transition returns distinct previous and next values.

## 5. State invariants

Validation checks in fixed order:

1. every live-note map key equals the chain-bound commitment of its opening;
2. every live commitment appears in commitment history;
3. no live note's derived nullifier is already spent;
4. recovery history contains no duplicate output commitment;
5. recovery-history commitment keys exactly equal commitment history;
6. checkpoint-local accepted effects contain no duplicate intent;
7. every checkpoint-local accepted intent exists in global intent history;
8. every checkpoint-local accepted effect names a body in this checkpoint;
9. ordered body history has no duplicate body identifier;
10. checkpoint-local bodies are the exact suffix of ordered body history;
11. checkpoint body IDs and body bindings have equal lengths;
12. checked live-note value plus fee pool equals cumulative native issuance.

The current state-invariant categories are listed in
`checkpoint-parameters.json`. They share the stable outer code
`kernel.invalid_state`; the Rust variant names are not separately frozen wire
codes. Failure invalidates the whole checkpoint call.

## 6. State digest

The canonical state-digest projection excludes `checkpoint_id` to avoid a
self-hash cycle. It encodes, in order:

```text
u8(1)
chain_domain
profile_domain
previous_checkpoint
checkpoint_index:u64
live_notes:u32 count || sorted(commitment || NativeNoteV1)
nullifiers:sorted-unique list
commitment_history:sorted-unique list
recovery_history:ordered list
ordered_body_history:ordered list
bodies_in_checkpoint:ordered list
body_bindings_in_checkpoint:ordered list
accepted_intents:sorted-unique list
accepted_effects_in_checkpoint:ordered list of body_id || intent_id
native_issued:u128
fee_pool:u128
```

Then:

```text
state_digest = H("Silk-Transparent-State-v1", canonical_state_projection)
```

All `H` operations use the framed SHA-256 transcript defined in `README.md` and
`native-kernel-spec.md`; they are not raw concatenation.

## 7. Checkpoint identifier

After successful interval execution, the role sets:

```text
previous_checkpoint = base.checkpoint_id
checkpoint_index     = checked_add(base.checkpoint_index, 1)
```

It records current body IDs, matching content bindings, and accepted effects;
extends ordered body history; validates the complete resulting state; and
derives:

```text
checkpoint_id = H(
  "Silk-Transparent-Checkpoint-v1",
  chain_domain,
  profile_domain,
  u64_le(checkpoint_index),
  previous_checkpoint,
  state_digest
)
```

Checkpoint zero uses index zero and a zero predecessor, validates the
NativeKernel genesis projection, derives its state digest, and applies the same
checkpoint-ID equation.

## 8. Reduced Gate A genesis receipt

The public host returns checkpoint zero together with a deterministic A2a-5
receipt. Since A2a-6, this receipt is detached diagnostic evidence for the
no-value derivation boundary. It is not the normative
`GenesisObjectTemplate`, the final `GenesisObject`, a `VertexId`, or a
`GenesisId`.

The chain-independent receipt template encodes:

```text
u8(1)
protocol_major:u32
zero32 || u8(1)  // five-input genesis commitment recipe
zero32 || u8(2)  // chain-domain recipe
zero32 || u8(3)  // protocol-manifest-hash recipe
zero32 || u8(4)  // profile-domain recipe
zero32 || u8(5)  // transparent checkpoint-zero state-digest recipe
zero32 || u8(6)  // transparent checkpoint-zero identifier recipe
```

The 203-byte template rejects any unknown version or recipe, nonzero derived
placeholder, truncation, or trailing byte. At the A2a-5 boundary, its canonical
bytes were hashed under `SilkNode-Genesis-Object-Template` and occupied the
object-template input of the five-input test genesis commitment. That digest is
retained only for historical fixture reproduction. Since A2a-6, it is not a
genesis-identity input: `silk-profile` supplies the distinct 236-byte `0xa0`
non-PoW state-anchor template, and the separate leaf `silk-genesis` crate
materializes and verifies the 230-byte `0xa1` final object.

After exact profile activation and checkpoint-zero materialization, the host
encodes the 197-byte receipt:

```text
u8(1)
protocol_major:u32
genesis_commitment:Hash32
chain_domain:Hash32
protocol_manifest_hash:Hash32
profile_domain:Hash32
checkpoint_zero_state_digest:Hash32
checkpoint_zero_id:Hash32
```

Receipt construction recomputes every field, including the checkpoint ID from
the recomputed state digest, and rejects if that ID differs from the identifier
stored in the supplied state. Canonical decoding creates only an untrusted
candidate; verification first requires the same chain/profile and an exact
valid checkpoint-zero state, then compares fields in the order shown. Neither
receipt bytes nor any receipt hash feed back into `genesis_commitment` or
`chain_domain`. The A2a-6 leaf may consume the already verified receipt values
from `MaterializedGenesis`, but the receipt encoding and historical template
digest remain detached from genesis identity.

## 9. Structural call behavior

The explicit execution chain is compared with the base state before the
execution profile. An interval requires at least one body, at most 1,024
bodies, and at most 4,096 transactions across all bodies. Transaction-count and
checkpoint-index arithmetic are checked. A body identifier may occur only once
in the entire checkpoint lineage. Invalid base or resulting state rejects the
whole call.

On success, `Transition.previous` is an unchanged value-equal clone of the
supplied base, `Transition.next` is the sealed snapshot, and `rollback` returns
the unchanged previous snapshot. Replay from the same base, literal execution
context, and ordered bodies MUST reproduce decisions, canonical evidence bytes,
state digest, and checkpoint ID.

Checkpoint ABI 3 adds two top-level evidence codecs:

```text
c5 01  CheckpointStateWireV1
c6 01  TransitionV1
```

`CheckpointStateWireV1` encodes, in order, chain domain, profile domain, stored
checkpoint ID, predecessor, index, live notes, nullifiers, commitment history,
recovery history, ordered body history, current bodies, current body bindings,
accepted intents, current accepted effects, native issued, and fee pool. The
logical native fields match `NativeStateProjectionV1`, but they are inlined in
checkpoint-state order; there is no nested `c0 01` prefix. The top-level bytes
are distinct from the state-digest projection and do not change the version-1
state digest or checkpoint-ID equations.

`TransitionV1` encodes previous checkpoint state, next checkpoint state, and
the complete decision sequence. Every aggregate uses canonical `u32` counts;
growing histories use remaining-byte/minimum-element allocation guards instead
of a new protocol-lifetime cap. Current bodies and bindings remain bounded by
1,024 and decisions/effects by 4,096.

Decoding produces only unverified candidates. Checkpoint promotion MUST match
the bound host chain/profile, validate every state invariant, recompute and
match the stored checkpoint ID, and match a separately supplied trusted
checkpoint-ID pin. Self-consistency alone is not a trust root. Transition
promotion MUST begin from a separately trusted base and exact ordered bodies,
re-execute NativeKernel evaluation and checkpoint sealing, exact-compare every
candidate field, and return the recomputed transition. A decoded native result
cannot be passed into the sealer.

## 10. Role boundary and capability status

Checkpoint reads the canonical order and complete native state projection and
writes the checkpoint projection listed as review metadata in
`checkpoint-parameters.json`. It does not acquire NativeKernel authority by
serializing that role's output.

The Rust implementation enforces a native-only state view and private typed
effects before checkpoint materialization. Capability declarations and Rust
visibility are still not a runtime sandbox. A combined façade must bind both
descriptors; binding only NativeKernel does not identify checkpoint
serialization or sealing.

## 11. Security boundary

The vectors and detached cross-language transition corpus are finite. They are
not a complete second client, an exhaustive oracle, or proof of consensus
safety.
Checkpoint hashes do not establish body authenticity, persistence, snapshot
availability, PoW finality, privacy, valuable-operation safety, source/build
provenance, executable identity, or runtime measurement.

This Checkpoint version does not define or enforce the A2a-6
`GenesisObjectTemplate`, final non-PoW `GenesisObject`, `GenesisId`, or release
pin; those are owned by `silk-profile` and the separate leaf `silk-genesis`
crate. A2a-6 likewise does not define the first mined child's anchor-reference
validation, RandomX/bootstrap key, target or DAA policy, timestamp, nonce,
body/root algorithms, or reward. Those first-child PoW rules require a separate
reviewed contract and vectors.
