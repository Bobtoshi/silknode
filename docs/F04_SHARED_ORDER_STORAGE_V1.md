# F0.4 shared physical ordering history

Follow-up: [bounded physical publication](F04_STREAMING_ORDER_PUBLICATION_V1.md)
keeps these exact bytes and charges while replacing all-page payload staging
with a metadata-only plan and page-at-a-time writer. The horizons are unchanged.

This prototype changes local physical storage, not graph ordering or consensus.
The canonical `SNF04OR1` bytes, their SHA-256, and generation `Record.order`
remain identical. Admission, checkpoint publication, clock flush and cold replay
use a typed reader that returns those original bytes, never a saved validity
claim. Ordinary replay must still derive graph/crypto/economic validity afresh.

## Why this slice is needed

Saving a full order prefix for each admitted vertex retains a quadratic number
of ID bytes: prefix lengths 1 through N retain N(N+1)/2 IDs. The previous order
detachment reduced resident vectors but still saved every complete raw prefix.
This slice shares immutable leaf/branch pages across newly written prefixes.

It does not change ordering/replay CPU complexity. Derivation and reconstruction
still visit the bounded current order. Reorganisations may change every page;
there is no general constant-cost reorganisation claim. No existing raw objects
are migrated, rewritten, deleted or pruned, and old unreachable files stay charged.

## Local representation and exact-byte reader

- Orders with at most 64 IDs retain the original `<canonical-sha>.obj` file.
  Any existing large raw order also remains preferred, unchanged. Damage to an
  existing raw object cannot fall through to an alternate representation.
- A new larger order uses `<canonical-sha>.ord`, exactly 116 bytes:
  `SNF04OT1` (8), the original canonical order header (76), root-page SHA (32).
  The descriptor's own hash is NOT the canonical order ID. It is never returned
  as canonical bytes, and the generic raw-object reader does not interpret it.
- Immutable auxiliary pages are ordinary `<page-sha>.obj` objects. Each has a
  12-byte header followed by populated 32-byte rows only. A leaf has magic
  `SNF04OL1`, row count (u8, 1–64), reserved zero (u8), and base leaf ordinal
  (u16 little-endian), followed by vertex IDs. A branch has `SNF04OB1`, level
  (u8, exactly 1 or 2), child count (u8, 1–8), and base leaf ordinal (u16 LE),
  followed by child-page hashes. The root is level 2/base 0; level-1 bases are
  multiples of 8. Position, depth, populated child counts and partial-tail rows
  must match the canonical count exactly. No trailing or unpopulated slots exist.
- Eight-way fanout and two branch levels cover the unchanged 4,096-ID horizon:
  at most 64 leaves + 8 intermediate branches + 1 root = 73 pages. One leaf is
  at most 2,060 bytes, one branch at most 268 bytes, and reconstructed canonical
  output at most 131,148 bytes. This is not a whole-process RSS guarantee.
- Every physical read is anchored to an owned held directory FD, with no final
  symlink following, regular/single-link/owner/size checks, stable device/inode/
  length/mtime/ctime checks and exact page hashes. Complete reconstruction must
  match the canonical filename hash. Live `CoreOrder` additionally checks its
  freshly derived graph/total commitments/count. No successful payload or
  validity cache, peer order constructor or imported HEAD authority is added.
- Missing/damaged nested pages refuse the complete read, not a partial prefix.
  Their error is a STOP outside the existing previous-HEAD recovery classifier.
  If both raw object and descriptor are absent, ordinary legacy missing-object
  handling remains; this is not a new recovery, repair or adoption route.

For an append after initial shared-tree seeding at 65 IDs, at most one new leaf,
one intermediate branch and one root are needed, plus one 116-byte descriptor.
Unchanged pages deduplicate by freshly derived exact bytes and hashes. The first
65-ID shared representation seeds four pages. This bounded append-sharing claim
is physical storage only, not a throughput or native acceptance claim.

## Publication and budgets

All pages are derived from fresh receiver-produced canonical bytes. Before any
write, the writer verifies existing shared objects, requires an active admission
or replay marker for a new shared representation, and reserves the new physical
pages/descriptor plus the ordinary data/state/head and publication overhead.
An existing exact order needs no new marker or order file on clock-only flush.

The existing 4 KiB rounding PLUS 4 KiB per-file accounting charge is retained.
The 8 MiB object/16 MiB group, 14 GiB pause/4 GiB host margin, 4,096 history and
20,000 generation bounds are unchanged. Failed reservations do not write; failed
write reservations remain charged and stages are retained. Uncertain new writes
poison the writer and do not trigger same-attempt previous-HEAD adoption.

Data/state, new auxiliary pages and the synced no-replace descriptor precede the
unchanged atomic HEAD/PREVIOUS publication tail. Descriptor stages are created
and renamed relative to the held directory FD. The caller's original cumulative
budget spans planning, each physical source read/write and the final pre-HEAD
check; it is not reset or enlarged. Native/cooperative deadlines elsewhere are
unchanged. A completed HEAD is not relabelled by a new post-publication budget
decision. Existing post-commit host-margin refusal remains unchanged.

Older binaries do not understand a new `.ord` representation. Do not run one
against a newly paged store. This prototype source milestone neither deploys a
runtime nor activates a protocol; public alpha/history/release defaults remain
unchanged. Existing legacy raw stores need no in-place conversion.

## Focused verification

The source contains seven synthetic storage checks: closed codec/horizon edges;
the in-memory all-prefix sharing model; 64–256 disk-prefix publications and cold
typed reads; fence/quota/expired-budget refusal before writes; changed/missing/
hardlinked/symlinked later-leaf refusal without HEAD adoption; hash-valid wrong
root shape/context/trailing framing and raw-damage precedence; and preserved
failed descriptor stages/no overwrite. The model covers prefixes 65–4,096 without
writing thousands of snapshots to the 64 MiB test volume. Its shared-order charge
is below half the legacy raw-order charge under the SAME conservative accounting.
It is not a measurement of whole-node storage or a capacity lift.

Five existing order binding/creation/graph-refusal checks and one raw held-FD
reader check cover the affected integration boundary. Reproduction requires the
separately qualified Linux containment: owned capped test storage, host margin
outside it, original resource/foreground bounds, and locked offline release build.
For that environment, the focused lib-test filters are `store::order::tests::shared_order_`,
`disk_order_`, and
`store::tests::disk_ancestry_owned_reader_bounds_types_hashes_and_directory_anchor`.
No work or payment proofs are generated, no historical native replay is run, and
no network listeners or live node/seed services are changed by these checks.

Native paged-order admission/checkpoint/cold-process operation is still UNPROVEN.
This component evidence does not establish practical speed, privacy, independent
network acceptance, wallet recovery, whole-core completion or release readiness.

### Exact-source result (2026-10-04)

Locked offline Rust 1.93.0 release lib/test build succeeded: service 38.900s,
CPU 38.836s, peak 410.2 MiB, swap zero. Final focused checks all passed under
3 GiB/no-swap, one-CPU, four-task, 60-second per-check containment:

| Check | Tests | Test / service time | CPU / peak memory |
| --- | --- | --- | --- |
| Synthetic shared storage | 7 passed | 1.26s / 1.304s | 1.252s / 6.3 MiB |
| Existing order binding/refusal | 5 passed | 0.06s / 120ms | 69ms / 8.4 MiB |
| Raw held-directory reader | 1 passed | 0.00s / 56ms | 23ms / 2 MiB |

Production changed-span Clippy: zero diagnostics. The 156 outside-change
baseline diagnostics are separately reported; test source was compiled, not
claimed lint-clean. Initial accounting assertions omitted the existing extra
4 KiB per-file reservation and were corrected without changing policy. An
intermediate runner expected two matching old tests but actually ran five,
all passing; its expectation was corrected without changing the tested source.
Original failure/runner/lint outputs remain preserved, not relabelled as passes.

Exact tested ELF SHA-256:
`2b33d444ea727dd668ca17f6517061bfd7c0ded0260d500b55d8b23a24e12e56`.
Focused result SHA-256:
`c2b7c32bba27c09f16590cf7eca0f801db61cbe58c57cc22eb5317ef5ca5f423`.
Changed-span lint result SHA-256:
`8f4a701475f7d8729b096e25e7c0562da4bc4ec08cf60be78e19f88fb0e994ce`.

| Node source | SHA-256 |
| --- | --- |
| `src/store.rs` | `2ba17c4e2db987c626aa782eeaa27d865c4ef5f5e1cfb51e32480afe67b276b6` |
| `src/store/order.rs` | `3bb07d21f85ae5bc6f0e431d98d3d9feac277121de5e1df011620380531212ec` |
| `src/store/order/tests.rs` | `0e559d0902564b1acc38d1a28b0fd30b5e319e82a41f4c56ba20f639582dc291` |
| `src/core/order.rs` | `4973bda2be7c2d8c69550a9c9e2fc2b39e9d8bb5326af149cd10459d99068816` |
| `src/node.rs` | `4ec72773344f365e4d6f10653e38810f905cf327e16512d4b7953b0f2cfb6f18` |

## Larger-history gate is FAILED, not silently repaired

The separately approved source-26 native 3,080-carrier run stopped ingesting
candidate 1,361 (ordinal 1,360) with
`Paused("cumulative foreground CPU/wall budget")`. Last complete generation:
sequence 1,530, 1,360 vertices, checkpoint 170, Ready. The active job marker and
failed store remain preserved. Full 3,080/checkpoint-385/state comparison was not
reached; no stage-one receipt was emitted and the second cold OS process did not
start. Aggregate RAM/disk/run limits were not exhausted. CPU-versus-wall branch
and finer internal ingress phase were not recorded, so neither is attributed.

Native result SHA-256:
`81870c5e98b49839771a1bda638c2c178450ba23f9b094caf149770d8e19d369`.
The original stores, old evidence and live seed were not reused or changed.
No rerun, failed-store repair/adoption or budget lift occurs in this source slice.
Shared storage is independently necessary; it is NOT an evidenced fix for that
foreground refusal. A new native run requires its own exact bounded authority.
