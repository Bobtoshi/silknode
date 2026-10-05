# Native shared-order boundary and cold continuation

Private, valueless acceptance slice, 5 October 2026. The implemented
[page-scanned inspection](F04_STREAMING_HISTORY_INSPECTION_V1.md) and
[bounded publication](F04_STREAMING_ORDER_PUBLICATION_V1.md) passed one fresh
72-carrier native operator journey crossing the 64-ID shared-order boundary,
including nine checkpoints and a separate pinned cold OS process.

This closes that changed-path native boundary only. It does not extend the old
source-30 [full 3,080-carrier result](F04_NATIVE_HISTORY_RESTART_V1.md) to the new
ELF, or establish beyond-4,096 capacity, native P2P, independent consensus peers,
churn, private cross-host wallet recovery, performance/privacy or release readiness.

## Exact execution

One new exclusive receiver was created on the existing 64 MiB capped test volume:
`/var/tmp/silknode-replay-pages-lab-v1/ancestry-fs/work/history-native-boundary-72-v1`.
The existing independently pinned 3,080-carrier public manifest supplied only
its first 72 original carriers, in complete frames 32 + 32 + 8. No mining, new
proof generation, wallet-key transfer or failed-owner reopening occurred.

Five sequential one-shot CLI processes completed: initialize; ordinary pinned
reopen plus ingest/reconcile to 32; the same to 64; the same to 72; and a separate
final pinned reopen/resume at 72. Each receive window was statically bound before
store opening, then every new carrier passed ordinary native work/crypto/parent/
order admission and Ready reconciliation. The final cold process replayed original
full retained records and semantic transitions, not cached validity or a snapshot.

The outer supervisor froze each successful operator-produced HEAD outside the
node directory and supplied it to the next process. All five phases were Ready
at 0/32/64/72/72 vertices and 0/4/8/9/9 checkpoints, with no previous-head recovery.
The final canonical order had 72 IDs and a real existing-format shared descriptor;
eight `.ord` descriptors were retained. Final cold parity was exact:

| Field | Before and after final cold process |
| --- | --- |
| Local HEAD | `2fe258d0c0358cf9c6a4a11d66985ffc637df3ed50217284fae62c41a219e545` |
| Canonical order SHA-256 | `918e0ccbe281d3f70a07a5f84966a4e291d257c98506e19fc3a8a3311763b58c` |
| Checkpoint 9 | `ab1996fc3d6920c6479f7dfd572023938716ed309a3bbb4b343e6f9cc07e0698` |
| State digest | `1cf9bd91ff60273b205607d76af2efac58c03fe14aa208313865b4886eb95d2e` |
| Public fixture fields | leaves 4; pool 299; burned 1; eligible cut 0 |
| Fresh receiver-derived hint | 72 of source total 3,080; hint only, not convergence authority |

## Resource and preservation receipt

Original per-vertex 2 CPU seconds / 5 wall seconds and checkpoint 10-second
allowances stayed unchanged. Each outer native unit retained one CPU, 3 GiB,
no swap, four tasks, at most 120 wall / 60 CPU seconds. Five units shared one
1,200-second monotonic window, with at most 300 CPU seconds from their caps;
there was no retry or replenished interrupted allowance.

Measured sum: **77.867 CPU seconds / 78.403 service-wall seconds**, aggregate
supervisor elapsed 79.150s. Largest reported unit peak 600.4M, swap zero. These
include repeated pinned startup/parameter/replay work and are not throughput or
network-speed measurements. The new production binary build separately passed
in 20.244 service / 20.213 CPU seconds, peak 262.3M, swap zero; only compiler
tasks used the existing 16-task exception.

All outer intents closed successfully, node ACTIVE_JOB/ACTIVE_REPLAY were absent,
and task UID processes were reaped. The original 4 GiB image's size/blocks and
nanosecond mtime/ctime were identical before/after every phase. Four older failed
64-byte markers remained. Only the existing SSH listener was present; no network
service, live seed, alpha release or valuable assets were deployed/activated.
The successful new owner, frames, receipts and frozen ELF remain preserved.

Production ELF SHA-256:
`ebff696f27a3e6f7ed101da3c7b4c6ab0d6674347ea03c56df66de3009dcf0cd`.
Native aggregate receipt SHA-256:
`1f8dfa7a66d9e8b16eca57f36ac70aaae75d6047ddc8cc6122fa23066395c847`.
Production build receipt SHA-256:
`ba9e01a6647780f6d107ed761da90b870537d1118d20d3e867bc98e9a82465a1`.
Outer runner SHA-256:
`afa317cb9ca1006508d49b9e51dbccb7be6315512bb6a207a4e1efe299bae534`.

Original receipts remain under `/var/tmp/silknode-replay-pages-evidence-v1/` as
`native-boundary-v1-result.json` and `native-boundary-cli-build-v1-result.json`.
The latter pins all exact six source files from the publication component plus
unchanged CLI SHA-256 `7c22cb3fd24eee48848ea335fe0344f1e569aae7c8b0c9f5c1481a411a9ebd85`.
Source is the signed public `585f0dc2c888fdf3113c46feb5c63ceb22082e9e` tree
`71db844e042743b3ac47b43b3bb0e4e49153bec3`; documentation-only follow-ups do not
change those Rust bytes. Full 3,080/cold and SSH-eight cases were not repeated.

The fixed ancestry directories, two-level order-tree geometry, reference snapshot
and reducer materialization costs, and coordinated graph/index/ledger/sync/
generation horizons remain the next sustainable-growth mechanism work. This
result is owner-executed evidence, not independent full-core acceptance.
