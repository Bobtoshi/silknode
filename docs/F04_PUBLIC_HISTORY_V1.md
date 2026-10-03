# F0.4 bounded public history source

`silk_f04_node::history::PublicHistoryV1` distributes full public carrier bytes
through the existing range codec. It is not a node-store importer, a verified
snapshot, a validity cache or a replacement for ordinary receiver admission.
This local distribution format is non-consensus and adds no protocol activation.

## Receiver boundary

Open an independently content-pinned manifest with an already admitted genesis.
Read one range, decode it with the existing `RangeBatchV1`, and pass each carrier
to `Node::ingest` with the ordinary parameters. Reconcile the node normally;
`Ready` is the node's derived state, never a source manifest claim.

The reader checks static candidate/body framing and context, **not** RandomX,
Sapling proofs, parent-derived difficulty, graph ordering or ledger execution.
Hash identity establishes exact bytes, not their validity. A malicious manifest
can advertise invalid work; ordinary node admission must reject it. Source HEAD,
checkpoint and state-object hashes are provenance/comparison claims only. Never
use the source HEAD as a receiving node's own retained-store pin.

No wallet key, wallet exposure journal, node HEAD/LOCK, persisted ledger state or
private repository history is an input. Public carriers retain their complete
encrypted transaction representations and original work proofs, not sidecars.

## Resource and file contract

- The existing 4,096 graph/order/ledger/sync inventory horizon is unchanged.
  The manifest is at most `176 + 4096 * 68 = 278704` bytes. Only bounded descriptor
  rows are retained; all carrier payloads are not loaded together.
- Requests contain 1–32 carriers. A terminal request is clamped to remaining
  rows; a start beyond the inventory or a zero/oversized count is refused.
  With the existing 90,000-byte carrier bound, encoded output is at most
  `1 + 32 * (4 + 90000) = 2880129` bytes. One carrier and its static decoded body
  are temporary working data; this is not a whole-process RSS guarantee.
- An owned open directory descriptor anchors every read. The final root path
  component cannot be a symlink. Intermediate root-path components are not
  independently authenticated; resolve the intended source before opening it.
  Subsequent root-path replacement does not redirect the held descriptor.
- Only `history.manifest` and lowercase hash-derived `.vertex` names are opened
  relative to that descriptor. Symlinks are not followed; descriptors are
  close-on-exec. Files must be regular, single-link, bounded and owned by the
  directory owner. The directory need not be owned by the consuming node UID:
  read-only public staging can remain owned by a separate administrator.
- Every read checks exact SHA-256 and stable device/inode/size/mtime/ctime before
  returning bytes. Every carrier is reopened and rehashed on every call; there
  is no successful-read or failed-read validity cache. A replacement containing
  the same exact authenticated bytes is not a new validity claim.
- Candidate ID claims must match the manifest row after static decoding.
  A bad later member refuses the entire request, with no returned partial batch
  and no node mutation. Manifest vertex IDs and carrier hashes must be unique.
- Blocking file I/O has no cooperative deadline here. Callers own aggregate
  wall/CPU/RAM/disk containment. Existing node foreground budgets remain intact.
  This reader grants neither an expensive replay budget nor more history space.

The existing 20,000-generation bound, per-vertex 5-second wall/2-second process-CPU
budget, checkpoint 10-second wall/CPU budget, RandomX mode/target, proof verifier,
consensus/commitment/wire/economic bytes, quota policy and release defaults are
unchanged. No pruning or claimed 4,096-record native acceptance follows.

## Closed local manifest bytes

All digests are 32 bytes. `SNF04HF1` has exactly a 176-byte header followed by
`count` fixed 68-byte rows; trailing bytes are refused.

| Offset | Width | Meaning |
| --- | --- | --- |
| 0 | 8 | `SNF04HF1` |
| 8 | 32 | Admitted genesis domain |
| 40 | 32 | SHA-256 of exact public local genesis bundle |
| 72 | 32 | Source-local HEAD provenance claim |
| 104 | 32 | Claimed final checkpoint ID |
| 136 | 32 | Claimed original state-object SHA-256 |
| 168 | 4 | Row count, little-endian |
| 172 | 4 | Reserved zero bytes |

Each row is claimed vertex ID (32), full carrier SHA-256 (32), and carrier byte
length (4, big-endian). Lengths must be 720–90,000 bytes. Carriers are named
`<carrier-sha256-lowercase-hex>.vertex`; the manifest is `history.manifest`.
The output is the existing `RangeBatchV1` framing, not a new network wire format.

## Current exact-source evidence

One locked offline release library/test build succeeded with Rust 1.93.0.
Five focused synthetic filesystem/framing/refusal tests passed in 0.20s;
service 243ms, CPU 227ms, peak 33MiB, swap zero. They include a full-size 4,096-row
inventory, terminal range bounds, duplicate/context/hash/shape refusals, changed
and missing later members, symlink/hard-link refusal, fresh reads after damage,
ID-claim mismatch and held-directory behavior. Synthetic work was never admitted.

One separately gated **static-only** compatibility check read the independently
pinned historical public export: all 3,080 full carriers in 97 ranges, with the
current genesis and candidate/body codecs. Test 0.04s; service 91ms, CPU 62ms,
peak 1.9MiB, swap zero. Native work evaluations, payment-proof verifications,
node opens, wallet/private-Git imports and newly generated proofs/work: all zero.
Both checks had 3GiB RAM, no swap, one-CPU quota, four-task and 60-second limits,
socket denial and read-only public input. Only owned synthetic test files were
writable on the existing 64MiB test filesystem.

Production changed-span Clippy: zero diagnostics, with 156 outside-change
baseline diagnostics separately reported. Test source was compiled, not linted
as a claim of whole-repository cleanliness. Initial documentation/cast lint
findings were corrected; the original outputs remain preserved. A native-test
build initially refused an unsafe UID call under `forbid(unsafe_code)`; only the
test harness was corrected to require the named outer task UID. No native
history run occurred on that failed build.

Exact tested ELF SHA-256:
`ebe864d77951f4114d5747c6e4930cc9eccd169c111b2d5230d9e2fda268cdc4`.

| Source | SHA-256 |
| --- | --- |
| `src/history.rs` | `e2cbb6a578f06ac435c15a870c34ad4c66d42542da96d575c668aff7ebbb8ba7` |
| `src/history/tests.rs` | `006b1e8e43a3bca0909b4bc7c22d1243a473f66b12405f009a2c0863fba240fe` |
| `src/lib.rs` | `e9115ed84f81f1b3cc205c9c1ce2962ec5dcc882e3a1235642add10c10bfbc0c` |
| `src/node.rs` | `c59b7b772aaa6a66af8a57664ece17fcc87e75d89d7fc20b094881603ee0a517` |
| `src/node/historical_tests.rs` | `19db9eef778431af60c9d1a30e71a123893b453bd3570ef36e51f6f915b25eac` |

These hashes bind the checks to source bytes, not to a claim of native larger
history, whole-core readiness, privacy, throughput or live deployment.

## Named historical input and the next native gate

The valueless historical corpus was authenticated against independently retained
source provenance, exported with read-only/no-atime descriptor reads, and staged
as public carriers only. No old node store is opened by the new reader.

| Public input / comparison claim | SHA-256 or ID |
| --- | --- |
| Public genesis bundle | `35c55cca9487f71a0a89d182cfbc3db9d546d2f5c5f9cca20c4aa7483c15caf9` |
| Domain | `8c0325387abf1c5ae3bbc8a02e91fc87fedfbde653e94343ea79152287d1b466` |
| Manifest | `c0a8902985b35bdf8ad152d8d959104842db05ca5aec418bcaaa8bd14c622d2d` |
| Retained source HEAD | `800874e5cd2b51b47ddb803bea7b25559c7bec2f752bec04411afe29ad69af81` |
| Independently retained predecessor HEAD | `76e462bd2ba8e7d412f3f4d69d79d055f29b1779c62e6f440f78b318c79e0560` |
| Claimed checkpoint 385 | `efbd7a79bdc8b07eb7ebfe67a1af5dd9a592114314c76e09f91c6e1603efd2da` |
| Claimed original state-object hash | `072370e3cd5553f436d40ed27ddede303f6f1e23c2f1a64407df46566dd7996e` |

The 3,080 original full carriers are 720–3,510 bytes each. Genesis plus carrier
payload is 2,229,534 bytes; the manifest is 209,616 bytes. Staging with inventory
metadata is 3,571,854 bytes. Advertised work 1 and 385 epochs are historical
claims, not performance evidence or a new ordinary-mining configuration.

Two ignored, compiled native tests are supplied for the **next independently
approved execution**:

1. `node::historical_tests::historical_public_ranges_ingest_and_reconcile_fresh_node`
   creates a fresh task-owned node, consumes all ranges through ordinary ingress,
   derives 385 checkpoints, compares the original state/checkpoint claims only
   after full native verification, and emits fresh local head/order/public-ledger
   pins. The existing bounded reconciliation and foreground budgets still apply.
2. `node::historical_tests::historical_public_history_second_process_cold_parity`
   freshly replays that new store from externally retained first-process pins,
   checks exact order and public executed/recovery/accepted-output history, and
   refuses duplicate credit on exact repeat. It never adopts the source HEAD.

They require `SILK_F04_LARGER_HISTORY_NATIVE=1` plus an exact separately qualified
task-volume/parameter/source contract. The flag itself grants no execution
authority and does not enforce resources. Default tests do not run them.
**Both native tests remain unexecuted and larger current-core replay UNPROVEN.**

The old native 3,080-record completion used older source, a different host and
different storage representation. It cannot substitute for these current-source
tests or prove current foreground deadlines, memory/storage costs or cold replay.
Original large-fixture private recipient keys were not retained, so public
history alone cannot establish cold wallet recovery. Independent two-host
transport, discovery/churn, wallet custody, practical-speed and privacy gates
remain separate. No live seed or service was changed by this source milestone.
