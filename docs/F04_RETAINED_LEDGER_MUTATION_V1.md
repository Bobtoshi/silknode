# F0.4 retained ledger mutation and rollback

Private, valueless research. Checkpoint execution now keeps old ledger payloads
disk-retained even when the admitted batch contains payments. Executed, reward,
accepted-output and recovery histories append only newly derived rows to an
immutable retained prefix. Nullifier/effect sets stage only touched leaves;
freshly read original leaves retain their original physical ordinal after a
logical split. Publication re-encodes current canonical ordinals and preserves
the existing literal 32/33 split geometry and 64-row history packing.

Recovery uses the same closed history implementation with its original opaque
row width, `SNF04RP1` bytes and recovery-specific durable page writer. This is
an internal implementation reuse, not a new external module or wire format.
Existing modular public APIs and explicit materialized compatibility snapshots
remain available.

Membership observations and staged edits are provisional. Completed execution
still freshly streams every hashed ledger collection, checks complete economic
and lineage invariants, and checks the original checkpoint budget. Rollback
freshly checks the complete selected receiver-derived snapshot against its
state digest and invariants, then reuses that immutable snapshot instead of
loading its whole historical payload. There is no saved validity/error cache,
received-state authority or fallback from a failed read.

Consensus, commitment, checkpoint, recovery/page, state-hash and DL1 bytes,
ordered at-most-once effects, work/proof/economic rules, the 4,096 history policy,
conservative cache charges, runtime budgets and release defaults are unchanged.
Auxiliary immutable pages may be written within the existing active fence before
a later failure; no completed directory/state/HEAD is returned on that failure.
Existing uncertain-write STOP boundaries remain in force.

## Memory scope

Old retained payload histories are not fully materialized for reducer mutation
or rollback restoration. Visitors hold page-sized payload working sets; mutation
holds newly derived rows and edited leaves. A normal durable eight-vertex
checkpoint appends eight executed/reward rows, at most 256 accepted-output rows
and 512 recovery rows under existing envelope limits. Set edits hold touched
leaves rather than all historical keys.

This is not constant whole-node memory or unbounded-history acceptance. Live
page directories and metadata still grow with history, deltas/output payloads
must exist, and multi-checkpoint scratch reconstruction can accumulate its NEW
suffix across steps before persistence, under existing cache/reference/replay
caps. Public compatibility views still explicitly materialize. Larger native
sync/restart/competing-branch/private journeys and coherent beyond-4,096 policy
integration remain separate gates; the cap is not lifted here.

## Changed-path evidence

Frozen test ELF:
`3e0ddc2215ab111f9e6d7bd34d5fbffc862e9be60d3ada4e2b215044856c87e1`.
Compiler-only build and eight exact focused checks PASS on the research VPS:

- Four history codecs: 129 retained rows plus 64 new rows reproduce literal
  pages exactly, share full old pages, coalesce the partial tail, preserve the
  original fork, and refuse a missing old tail or changed context without HEAD.
- Set edits: interleaved/max-key inserts reproduce literal splits/page IDs,
  isolate forks, reject duplicates, and refuse missing needed/unvisited original
  leaves or expired budgets. Historical prefix keys stay non-resident.
- Synthetic payment-row model: manifests, state hashes, forward/rollback DL1
  and all retained page IDs match the literal oracle. Removing each original
  collection's page refuses complete prior/current qualification; no HEAD.
  This model is not cryptographic acceptance evidence.
- Changed metadata-only preparation qualifies all collections and preserves
  explicit public materialization behavior.
- Recovery/history unfenced and uncertain durable writes refuse publication.
- Streamed set difference drains unused previous suffixes and refuses bad page
  bindings after the loader change.
- NEW instrumented genuine saved-carrier journey: actual payment scratch
  execution matches the original admitted checkpoint with all six payload
  prefixes retained. Opposite ingress order between two same-host receivers
  causes an actual checkpoint rollback and two-parent merge; the selected
  rollback snapshot has zero staged payloads and no materialized old prefix.
  Carrier/order/state parity, same-process cold reopen and exact-repeat no-new-
  credit pass. Only authenticated existing public carriers are consumed: zero
  new mining, generated proofs, wallet secrets or valuable assets. The inherited
  `new_vertices=2` log counts structural sibling/merge carriers, NOT newly mined
  work; the new gate explicitly reports `newly_mined=0`.

Build: 53.060 service / 52.984 CPU seconds, peak 452.6 MB, swap zero.
Native fork/payment check: 24.885 service / 24.310 CPU seconds, peak 582.8 MB,
swap zero. Synthetic checks each peak at most 9.1 MB. Checks use one CPU,
3 GiB/no swap/four tasks, 120 wall/100 CPU seconds; compiler-only tasks use the
existing 16-task exception. Vertex/checkpoint budgets are unchanged.

Fresh native owner on the existing capped 1 GiB volume:
`/var/tmp/silknode-replay-pages-lab-v1/extensible-ancestry-native-fs-v1/work/retained-mutation-native-fork-v1`.
All successful phase intents close, task UID processes are reaped, neither new
receiver has an active marker, and original 4 GiB image size/block/mtime/ctime
pins are unchanged. Older failed/diagnostic owners are not reopened.

No unchanged 16/24/520/3,080 case is rerun; older results remain attached to
their own frozen ELFs. No P2P, independent-host consensus, wallet recovery,
separate-process cold-success, privacy/speed or release acceptance is claimed.
Existing unused resident helper warnings remain; this is not lint-clean.

Receipts in `/var/tmp/silknode-replay-pages-evidence-v1/`:

| Receipt | SHA-256 |
| --- | --- |
| `retained-mutation-build-v1-result.json` | `8898beaa7f5a98b62ea31fd8d6073fb9f6f0b6585fe51759f12ae19a8670ad29` |
| `retained-mutation-check-v1-result.json` | `7fd03578cbae38dc7a1a00f25b21351d309d685266b06c0aab3079de50fd64ef` |

Compiled changed source under `prototype/crates/silk-f04-node/src/`:

| Source | SHA-256 |
| --- | --- |
| `core.rs` | `eee56fa45d0b37516832b9e0d98fc129fca6b68c2079b3ade18f2585b3e526ca` |
| `state.rs` | `a3275b4e2967f9a0a88dbfabef9463ae098adb080f35cdda6d82e79223e1d260` |
| `state/history.rs` | `55ec3b214e9e29e143733a10f5aa56dee9a9b6b833743b80870a9083d4cacf3d` |
| `state/recovery.rs` | `209d32b1995de27dd63fb91dddc05c79436213878d81dde5989571d23c3c617a` |
| `state/sets.rs` | `eb475a7d6a06191d7032e47f56d53ca920bfee050fc0fe1e3ec05e6f410c7429` |
| `node/historical_tests.rs` | `e859620a0f89eca2714ac18afe241f8870d8890c776133a41cfa64e4595bda72` |
| `node/fork_tests.rs` | `e8e16031a46fd23a21be8c162ef824b00f221636a36ca1c2c0dbc5de63940ae0` |
