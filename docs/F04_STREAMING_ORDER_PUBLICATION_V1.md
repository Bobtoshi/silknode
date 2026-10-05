# F0.4 bounded physical order publication

Follow-up: the exact changed Rust source passed the
[72-carrier native shared-order/cold boundary](F04_NATIVE_HISTORY_BOUNDARY_V1.md)
on its separately frozen production ELF. Historical component evidence below
remains distinct; no full-3,080 or beyond-horizon result is transferred.

Private, valueless implementation follow-up to
[bounded history inspection](F04_STREAMING_HISTORY_INSPECTION_V1.md),
5 October 2026. The production order writer now walks physical pages instead
of constructing/retaining the entire tree's payloads before selecting new pages.
Existing canonical order bytes, page bytes/hashes, descriptors, generation
records, HEAD/PREVIOUS publication and all resource/default limits are unchanged.

## Two walks, one original budget

Planning derives the original fixed tree in depth-first order, holding one
derived page payload, its matching checked-read buffer when present, and two
directories of at most eight child hashes. Every
existing page is freshly checked against its exact expected bytes. Missing pages
retain only address/length metadata in a bounded map (at most 73 entries at the
unchanged horizon), not their payloads. Existing complete orders are checked
page-by-page against the caller's exact canonical bytes without reconstructing
another full preferred-order buffer; legacy raw reads remain bounded whole-object
reads. The canonical input supplied by the caller still exists in memory.

The same conservative rounded per-file charges, group/host/store bounds and
active transition fences reserve all writes before publication. A second walk
regenerates each planned missing page immediately for writing. Its exact length,
complete plan consumption and regenerated descriptor must agree before syncing
pages/descriptor and reaching the original HEAD publication tail. No second
allowance is allocated; the original cumulative budget spans both walks and
physical reads/writes. Failures retain charged files/stages and stop the writer;
no same-attempt repair, adoption or previously failed owner reopening is added.

Depth-first physical write order differs from the old payload-vector walk, but
all immutable objects and the synced no-replace descriptor still precede HEAD.
The unchanged old vector builder is test-only, as an exact independent
representation oracle. No durable version, migration, pruning or deletion exists.
This is not a new finality or consensus mechanism.

## Exact-source checks

Locked/offline Rust 1.93.0 release lib-test build passed on the research VPS:
service 46.137s, CPU 46.043s, peak 425.1M, swap zero. One new combined synthetic
check compared every page and descriptor with the old builder at 65, 66, 511,
512, 513, 4,095 and 4,096 IDs; verified metadata-only plans, exact reservation
charges, actual publication, deduplication, a cold typed read and expired-budget
refusal. It passed in 0.02s (service 62ms, CPU 41ms, peak 1.8M, swap zero).
The affected pre-write fence/quota/expired-budget case also passed (service 55ms,
CPU 35ms, peak 2M, swap zero), preserving HEAD/files on refusal.

These are physical-storage models, not native work, checkpoint or peer tests.
No already-passed SSH-eight-carrier or 3,080-carrier/cold case was repeated or
transferred to this source. No new proof generation, native replay, listener,
seed runtime, valuable operation or Mac build/test computation occurred.

| Changed source | SHA-256 |
| --- | --- |
| `src/store/order.rs` | `338bcce2903387ddbf9c6c9ee1bbd15dd32e28a2b3b2dbc3e623894ac4e5ab28` |
| `src/store/order/tests.rs` | `8baf2986c794c696914c5f4b3c1ff59aaf88919eef7763fb6bc2e57e0edb1aac` |

Frozen test ELF SHA-256:
`fdef2d6f82e0c650984d56e10cae5c3dd5b758dc745724512ababdc4ba04f6ed`.
Build receipt SHA-256:
`e2176c4618ee33a8e5e1a68780665e1630f3b358e309f9ee814f14e10adfb325`.
Focused receipt SHA-256:
`04e9d2a95c3131e8f182f99e3762d8f1dd375bdf061f3824a91e0c757bf4aae2`.
Original receipts remain under `/var/tmp/silknode-replay-pages-evidence-v1/`
as `streaming-publication-build-v1-result.json` and
`streaming-publication-check-v1-result.json`.

This removes another history-sized payload staging cost, not reference snapshot
derivation or full ledger reducer costs. The two-level order-tree geometry,
fixed ancestry directory and coordinated graph/index/ledger/sync/generation
horizons remain. Beyond-4,096 operation, indefinite history growth, whole-process
memory bounds, native P2P, independent consensus peers, private cross-host payment
and defensible performance/privacy evidence remain unmet. No capacity-only raise
or whole-core/release acceptance is implied.
