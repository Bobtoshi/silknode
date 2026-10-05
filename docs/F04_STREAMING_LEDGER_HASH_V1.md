# F0.4 streamed ledger state hashes

Private, valueless research. This change removes full retained-collection
materialization from state hashing; it does not complete bounded execution,
lift the 4,096 history policy, or establish new native/payment acceptance.

## Implemented mechanism

Nullifiers, effects, recovery ciphertexts and public rewards feed private
page visitors into a local hash accumulator. Retained reads own one page at
a time (plus one key or typed row), qualify the complete object hash and
inode through the existing reader, and check domain, magic, ordinal, count
and exact collection length. Set visitors also check strictly increasing
keys across page boundaries. Observations are provisional until every page
and the final budget/count check succeed; no digest or validity cache escapes
on failure. Resident reward encoding reuses one row-sized buffer.

The hash inputs remain exactly label-length byte, label, domain, little-endian
collection count and canonical row bytes, followed by the unchanged outer
state hash. Consensus, checkpoint, page and descriptor bytes, resource bounds
and defaults are unchanged. Page directories remain retained metadata; this
is not an assertion of constant total node memory.

## Focused evidence

All compute ran on the authorized research VPS. The compiler-only build and
three focused checks passed on test ELF
`cfc16d905a277a7bf9de496a80dec1a136290e5fa131cd8ea8717e7b5f907454`.

- New synthetic resident/retained comparison against the previous literal
  collection hash oracle; each collection's late page is separately missing,
  tampered and hard-linked. All failures refuse a hash. Restored pages match
  the original hash; manifests remain unchanged and no HEAD is published.
- Expired budget, short provider and extra provider observations refuse.
- Existing literal paged recovery hash/reversible-delta and ledger-set hash
  oracles pass.

Build: 50.957 service seconds / 50.878 CPU seconds, peak 435.3 MB, swap zero.
Checks combined: 359 service ms / 257 CPU ms, maximum peak 9 MB, swap zero.
These are synthetic economic/storage models, not admitted private payments,
recovery proof, independent consensus peers, or a native checkpoint journey.
No previous 72/520/3,080 native run was repeated or relabelled for this ELF.

Receipts under `/var/tmp/silknode-replay-pages-evidence-v1/`:

| Receipt | SHA-256 |
| --- | --- |
| `streaming-ledger-hash-build-v1-result.json` | `99db00f931294d000297b28d3d04f90c79dc2adfe637b18b5c87823ee7fba7dd` |
| `streaming-ledger-hash-check-v1-result.json` | `f6962ceb47633646e8c91c937ad3a6ba1cbfb389618af30718499a7f63441487` |

Exact compiled source SHA-256:

| Source under `prototype/crates/silk-f04-node/src/` | SHA-256 |
| --- | --- |
| `state.rs` | `dd0c878b8d79eeacb07da38b825fc60daf017d8416e9741f8e585de196932902` |
| `state/history.rs` | `1613540f45ba9d015b16f28ca9ba70a2e47b40850e1d1a922dc9fcab4a0a2660` |
| `state/recovery.rs` | `424f4459c43da220e60752915526099e44f472ee487d6c5677b17de1f0e87450` |
| `state/sets.rs` | `2d82c7f3548928f46d8cbbe97b6f6938cc3847957913c4c45c45ebbcba4d67b4` |

## Still required

Actual reducer mutation/rollback and public compatibility views still
materialize histories. Removing those loads needs its own coherent mutation,
validation and failure-atomicity implementation. Physical ancestry/order
extensibility is separate from integrated growing-history capacity and native
sync/restart/competing-branch/private-payment acceptance.

[Streamed forward deltas](F04_STREAMING_FORWARD_DELTA_V1.md) subsequently remove
whole-collection loading from forward delta construction and add changed-path
nonempty native replay evidence on their own frozen ELF.
