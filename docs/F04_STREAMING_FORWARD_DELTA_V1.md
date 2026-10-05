# F0.4 streamed forward checkpoint deltas

Private, valueless research. Forward delta construction no longer materializes
complete executed, nullifier, effect, recovery or reward collections to emit
one checkpoint's changes. Reducer mutation, rollback restoration and public
compatibility views still materialize ledger payloads; total bounded execution
and integrated growing-history capacity remain open. The 4,096 policy is unchanged.

## Actual mechanism and preserved bytes

The executed-history visitor compares the complete current stream with an
operation-local previous-prefix comparison, qualifying every page before
accepting the exact previous prefix plus eight positions. Nullifier/effect
differences use an ordered merge with at most one 64-key decoded leaf per side,
plus the currently read raw page. Both streams finish, even when no additions
exist or a previous suffix is larger than the last current key. Every raw
page passes existing complete hash/inode checks plus context, kind, ordinal,
count, strict cross-page key ordering and exact collection length checks.

Recovery/reward visitors qualify the complete current collections while
staging only suffix rows in the local delta output. Count slots are filled
after the complete merge; the output is returned only after all source reads
and the final budget check succeed. Output storage is proportional to actual
delta bytes, not necessarily constant. Metadata directories remain retained.
Previous recovery/reward payloads are not newly treated as authenticated prefix
inputs: their lengths retain the previous serializer's meaning.

Existing `SNF04DL1` bytes, key ordering, suffix order, checkpoint/consensus hashes,
rollback serialization, budgets and publication semantics remain unchanged.
No disk write, HEAD publication, persistent validity or negative/error cache
is introduced by construction. Failed construction discards the local output.

## Exact focused evidence

Compiler-only build and four focused checks pass on frozen test ELF
`716db245e318d6a73febce30645f7f0dd0cc8a128cdd6d21fd705d02228a579a`:

- New independent previous literal collection serializer equals resident and
  retained streamed deltas. Missing, tampered and hard-linked late inputs
  refuse; restored inputs reproduce the bytes. Expired/reversed cursor cases
  refuse, state manifests remain unchanged, no HEAD is published.
- New merge case checks a previous suffix even with an empty current stream,
  and refuses wrong context/kind/ordinal/length and resident ordering.
- Existing flat recovery/reversible-delta and retained executed-history/delta
  oracles pass.

Build: 49.818 service / 49.747 CPU seconds, peak 426.4 MB, swap zero.
Four checks: 467 service / 328 CPU ms, maximum peak 9.1 MB, swap zero.
One unused compatibility helper warning remains; this is not a lint-clean claim.

## Changed-path genuine nonempty replay

The SAME frozen ELF passed a fresh isolated copy of 16 existing genuine,
payment-bearing historical carriers (five nonempty representations), ordinary
full admission/replay, exact two-checkpoint economics, and original checkpoint
and parent scratch reconstruction. Private counters remain pool 58/burned 2;
the commitment tree has seven leaves. Missing original sources/ledger pages
refuse snapshots, reducers, rollback scratch and forward deltas without
publication. Original supplied bytes remain unchanged.

Native replay: 12.070 service / 11.825 CPU seconds, peak 327.2 MB, swap zero.
One CPU, 3 GiB, no swap, four tasks, 120 wall / 100 CPU seconds outer bounds;
existing per-vertex/checkpoint limits remain unchanged. Fresh owner on the
existing task's capped 1 GiB volume:
`/var/tmp/silknode-replay-pages-lab-v1/extensible-ancestry-native-fs-v1/work/ledger-native-16-v1`.
The final deliberate damaged-directory cold reopen refuses and leaves an
`ACTIVE_REPLAY` STOP marker; that diagnostic owner is preserved, never adopted
or reopened. No old failed owner was opened. No new mining/proofs/wallet secrets,
native fork/reorg, P2P or wallet-recovery acceptance is claimed. This is not
separate-process cold-success evidence or beyond-4,096 admission. Earlier
72/520/3,080 native results remain attached only to their own frozen binaries.

Input HEAD: `99bf944b4b08e47b23fb07bc4d3ee3945cabcec41d33b58ed04cd1a967d7bcaa`.
Input checkpoint: `30d649c79dd019e9bc2aab051a14faeef58997b0b47ffa9ca077ef796e14c0ed`.

Receipts under `/var/tmp/silknode-replay-pages-evidence-v1/`:

| Receipt | SHA-256 |
| --- | --- |
| `streaming-ledger-delta-build-v1-result.json` | `47ca7fbe060dd7d909a245bfaa55df34d75d73b96abe715a78a853d44d84ff04` |
| `streaming-ledger-delta-check-v1-result.json` | `c28cdc0e57cf9843689a3cf222d890dde84b63d6cd1ef8e2433028583c525871` |
| `streaming-ledger-native-16-v1-result.json` | `ba4b7932f8b02f737b247ff06c2330412d85f38dad2bcf53f12a937b90ea9f10` |

Compiled changed source under `prototype/crates/silk-f04-node/src/`:

| Source | SHA-256 |
| --- | --- |
| `state.rs` | `de86a0e359ad62907d12ded2b31032ba4d4e3cda14aa9cc01041b270923a3838` |
| `state/sets.rs` | `ace7150087ea052859d4493e905a3411d4595c17be52ad9f7e992949954749e2` |

All build/test/native compute ran on the authorized research VPS. No changed
consensus/crypto defaults, cap lift, live service, valuable asset or expensive
unchanged-baseline repetition is part of this result.

[Selective checkpoint preparation](F04_SELECTIVE_CHECKPOINT_LEDGER_V1.md)
subsequently keeps unchanged private payload collections retained for an empty
admitted batch, with complete streamed invariant qualification. Nonempty
mutation and mutable executed/reward histories still materialize.
