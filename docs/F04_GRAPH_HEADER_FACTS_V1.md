# F0.4 qualified operation-owned graph header facts

This source slice removes another repeated checked-directory read path during
ordering. It preserves canonical fields and mandatory validation, but does not
yet prove the failed full-history native gate is fixed.

## Actual preceding gates (2026-10-04)

Source29 passed ONE fresh 1,361-prefix check under the original vertex2s CPU/5s
wall and checkpoint10s limits. It derived Ready/1,361 vertices/checkpoint170/
1,360 executed/no active job. Test652.70s, service652.754s, CPU584.663s,
peak753.7MiB, swap0, within20min/1000CPU/3GiB/oneCPU/four tasks. Its fresh HEAD
and exact result are recorded in [the preceding slice](F04_GRAPH_ORDER_FACTS_V1.md).

The subsequent new full3,080 first-process attempt FAILED at ordinal2,448,
candidate2,449, carrier SHA-256
`89ecd148474aecb59a2b494d0dcf51b089f2da6452591b6d066b3e299d6fdedc`.
The original cumulative refusal was detected at `GraphOrder`: CPU2.000403901s
against2s; wall2.040395417s against5s. CPU expired, wall did not. This is the
active boundary at detection plus cumulative elapsed time, NOT exclusive phase
cost or unique causal attribution. The full state/checkpoint comparison and
cold process were not reached; no fresh full-history pin receipt was emitted.

Test1568.21s, service1568.259s, CPU1392.526s, peak950.2MiB, swap0. The shared
one-hour/3300CPU and3GiB/oneCPU/four-task outer ceilings were not exhausted.
The new failed owner and active-job marker remain preserved without reopen,
repair, marker clearance, previous-head adoption or retry. All earlier failed
owners and the protected original join image remain unchanged.

Full first-process result SHA-256:
`014f41de85a3b526b039e6841f8191e6a339312bd99a274a4a6744c822a7ad2e`.
Full/cold causal-gate result SHA-256:
`0765638d0976e0b6c52264f4a20fde97371e1d08956c552f6f37bfba4144f007`.
Frozen full/cold plan SHA-256:
`8b843e87a7427f47f469ad133e18c6bf3154a05fc88aa83264345e9a08ba24eb`.

## Actual source mechanism

The node ordering `View` already freshly qualifies the complete bounded
ID/ordinal permutation against every vertex-directory slot BEFORE callbacks or
answers. It previously discarded that pass's header fields, then reopened
directory pages for contains/parent/work calls in lexicographic ID order. On a
hash-like ID inventory this repeatedly displaced its one-leaf cache.

The qualified View now owns each checked header's original parent shape and
u64 work alongside its IDs/ordinals. Parent vectors are explicitly capped at the
unchanged two-parent bound. Facts are installed ONLY after the entire directory
pass and final budget check succeed. No payloads, metadata, ancestry vectors,
imported validity, failed reads or cross-operation answers are retained.

Contains/parent/work calls resolve the requested ID through that complete
inventory, retain original graph-read budget accounting, and perform the
existing checked ancestry membership test for filtered Views. The sealed added
vertex retains its original private checked route. Before an inventory exists,
the original checked lookup path remains. Metadata and ancestry still use their
original source-checking paths. Strict ancestry reuses the fully qualified
ordinal instead of unnecessarily reopening an index leaf after endpoint checks.

The immutable graph borrow prevents reuse across publication. Owned bytes are
an operation snapshot, not a guarantee to re-read them after external file
mutation. Every new operation freshly qualifies its sources and refuses new
damage. The ancestor query retains only the original ID/ordinal inventory; its
qualifying View's temporary header rows are dropped before that search begins.
Scratch remains O(N): at most4,096 compact header rows and two32-byte parent IDs
per row, in addition to the existing160KiB ID/ordinal vectors on64-bit targets.
This is not graph-wide carrier retention, a paged engine, constant-cost
admission, whole-process memory assurance or sustainable-history proof.

No public API, borrowed interface, wire/consensus/commitment/economic field,
work/proof/ledger check, release default, budget baseline or horizon changes.
The preceding chain commitment facts and unchanged reference/fork fallback are
not modified. No plugin framework, bridge, public native pool, asset or fee work
is included.

## Exact changed-path VPS evidence

Locked/offline Rust1.93.0 release library/test compilation passed: service42.407s,
CPU41.588s, peak451.4MiB, swap0. Only the changed node package was rebuilt.
Compiler/lint alone had the separately human-approved16-task ceiling with
3GiB/noSwap/oneCPU/20min/1000CPU; tests/node/native retain four tasks.
The original four-task attempt failed in a compiler helper-thread target probe
BEFORE source compilation. Cargo subsequently reused that cached failure; the
exact cache was preserved and moved aside, not a broad target cleanup. One
private inventory-type mismatch was then corrected before the successful build.
No toolchain/dependency install or Mac compilation/test/work occurred.

Two affected synthetic checks passed under3GiB/noSwap/oneCPU/four tasks/60s,
read-only inputs, no network and the existing owned64MiB test filesystem:

- The shuffled-ID129-vertex disk chain matched the unchanged COMPLETE reference
  snapshot and eligible order. Original vertex budget, expired refusal, fresh
  missing metadata refusal, diamond fallback and staged130th-vertex parity pass.
  Budget-counted source calls were138 versus251 in the preceding same fixture.
  These are source-accounting hook calls, not all physical I/O or CPU speedup.
  Test0.22s, service267ms, CPU246ms, peak6.1MiB, swap0.
- The65-vertex directory-boundary check retained whole-prefix qualification
  before callbacks/credit, filtered membership, strict ancestry, warm ownership,
  fresh index/directory damage refusal and fresh ancestry checks. Work queries
  added no directory leaf load after qualification; qualified strict ancestry
  added no index leaf load. Test0.07s, service112ms, CPU91ms, peak3.6MiB, swap0.

No native work or proofs were generated and no failed owner was opened by these
checks. Production changed-span Clippy passed with zero diagnostics;156
outside-change baseline diagnostics remain separate, not repository cleanliness.

Changed compiled node graph source SHA-256:
`9881e770ed4aedc5630e941c4c3d10a60157955954c5754e60c9e88f7af44783`.
Exact tested ELF SHA-256:
`71e4b31c7fe75fceb29ece752629ac1552c4d236f4c2b2b6944ceb6526f6ea2d`.
Focused result SHA-256:
`d85f7e91293cbb0a42bb376ff6774951f2e6329e91fda5b062644725c70b65f8`.
Changed-span lint result SHA-256:
`5c97d41292bc4c5321fa54c89c3c91f2ba292c19c38847536f1b94f692513fa7`.

## Still unmet

The corrected source has not yet passed native full3,080 ingestion/cold replay.
Necessary fresh diagnostics require exact source/input/ELF custody and fixed
task-owned resource envelopes; no unchanged retries or failed-store recovery.
Restart/reorg at sustainable history, isolated two-host recovery, wallet custody,
whole-system privacy and practical speed remain separate unresolved gates.
Source review/component parity is not release or whole-core acceptance.
