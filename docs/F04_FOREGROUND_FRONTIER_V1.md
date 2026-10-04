# F0.4 operation-scoped frontier reads and admission diagnostics

This source slice reduces repeated checked source reads in delayed-key frontier
search. It also records the first cooperative admission-budget expiration with
its active call boundary and separately measured cumulative CPU and wall time.
It does not establish that the failed larger-history ingestion is fixed.

## Actual mechanism

Previously, each ancestry comparison in the delayed-key source search reopened
the ID index and target vertex directory before checking ancestry. The new
crate-private `GraphData::ancestor_query` creates ONE immutable operation for
that search. Before returning any answer, it freshly qualifies the complete
bounded ID/ordinal permutation against the vertex directory using the existing
checked inventory path. No caller supplies imported IDs or saved validity.

The query retains only the owned ID/ordinal inventory, one directory leaf, at
most four positive target descriptors, and one ancestry leaf. The unchanged
4,096-vertex horizon bounds the inventory to at most 160 KiB of ID/ordinal
vectors on a 64-bit target. A directory leaf has at most 64 rows; an ancestry
leaf is 64 bytes. Target descriptors are existing owned decoded entries, not a
graph-wide collection of carrier payloads. These are component bounds, not a
whole-process memory guarantee.

Every requested ID is resolved against the fully qualified inventory. A newly
loaded target must match its ID/ordinal binding; membership uses the existing
checked ancestry operation and the same original job budget. The working set
is capped at four targets even when the frontier and ordinary parents differ.
There is no negative/failed-read cache. Missing or damaged fresh sources refuse
the operation; they do not fall back to another branch or saved answer.

The immutable graph borrow prevents reuse across publication. Dropping the
operation releases its owned working set. Already qualified owned bytes are an
operation snapshot: they are NOT a promise to reopen every previously checked
file after an operator mutates it. A new operation freshly qualifies its sources
and must refuse newly missing/damaged input. Nothing is persisted as validity.

`PrefixCache::derive` uses this operation only when a delayed-key source search
exists. It retains the same reverse candidate search, four-member frontier,
strict ancestry rules and ordinary-parent comparisons. Every source candidate
is still fully reconstructed with its own ledger/cuts BEFORE deciding whether
it is usable. There is no cache-miss skip, source/key substitution or removal of
RandomX, Sapling, ordering, metadata, economic or ledger verification.

The mechanism addresses a source-grounded repeated-I/O cost. The old failed
candidate's exact phase was not recorded, so this is not retrospective proof
that ancestry I/O caused that failure. Whole-directory qualification has a
bounded up-front cost; native large-prefix CPU improvement is still UNPROVEN.

## Read-only failure diagnostics

`Node::admission_budget_failure()` returns the last live admission's first
cooperative budget expiration, if one was recorded. The public
`budget::AdmissionBudgetFailure` reports:

- active `AdmissionPhase` call boundary;
- elapsed monotonic wall time and optional elapsed process CPU time;
- original wall and CPU allowances;
- separate wall-expired and optional CPU-expired observations.

The trace is receiver-local memory shared with the moved worker budget. It is
not a second budget and never resets baselines on attach, worker dispatch,
yield, return or phase changes. Only the first failure is retained. Phases cover
decode/preflight/fencing, parent ordering/commitments/difficulty, frontier
inventory, source replay, frontier search, key construction, native work,
body crypto, metadata/order, durable publication and terminal closure.

This identifies the active call boundary at detection, not an exclusive CPU
profile: cumulative process CPU includes earlier phases and other threads.
Parked time still counts toward the original wall limit. It does not report
per-phase costs or prove a unique root cause.

The original cancellation-first and inclusive expiration checks are preserved.
Successful checks add no extra clock sample. On the original short-circuit wall
refusal only, a traced job takes an extra diagnostic CPU sample; its failure or
regression produces `None`, never changes that wall refusal. Other clock errors
retain their original error classification. All cooperative expiration errors
remain `Paused("cumulative foreground CPU/wall budget")`.

Reading the diagnostic after STOP grants no health, validity, recovery, retry or
adoption authority. `None` does not mean success: native termination, cancellation,
clock failures and other errors may leave no report. Cold replay does not import
or persist these traces. Existing native guards and active-job failure fencing
remain unchanged; SIGKILL may prevent any report from being emitted.

## Exact-source focused evidence (2026-10-04)

Locked offline Rust 1.93.0 release library/test build succeeded: service 44.300s,
CPU 44.223s, peak 404.7 MiB, swap zero. Seventeen focused tests passed under
3 GiB/no-swap, one-CPU, four-task, 60-second per-check containment, socket denial,
read-only inputs and an existing owned 64 MiB synthetic test filesystem:

| Check | Tests | Test / service time | CPU / peak memory |
| --- | --- | --- | --- |
| First-expiry diagnostics and STOP boundary | 5 passed | 0.03s / 74ms | 55ms / 8.4 MiB |
| Ancestry parity, scope, refusal and source count | 2 passed | 0.06s / 95ms | 77ms / 3.5 MiB |
| Existing quantum/cancellation/deadline checks | 5 passed | 0.12s / 158ms | 24ms / 1.8 MiB |
| Existing order binding/refusal checks | 5 passed | 0.05s / 107ms | 70ms / 8.4 MiB |

The 65-vertex disk-backed linear synthetic query produced identical 64 ancestry
answers while reducing **budget-counted source calls from 256 to 6**, under the
original two-second process-CPU allowance. This counter measures calls to the
existing source accounting hook, NOT all physical I/O; legacy direct ancestry
reads are not counted by it. This is neither a 42x CPU/throughput claim nor a
complete native parent-facts/key acceptance result. The branch fixture compares
all diamond ID pairs, strict self ancestry and missing IDs. Fresh missing later
directory/ancestry sources refuse, failures are not cached, the positive working
set stays bounded, and ownership is released on drop. Diagnostic checks cover
CPU-only, wall-only, both, unavailable CPU, first-failure preservation, worker
handoff, unchanged deadlines and post-STOP non-authority. The existing quantum
test deliberately panics its fixture worker; its expected panic is not a failed
test or a hidden native execution.

Production changed-span Clippy: zero diagnostics; the 156 outside-change
baseline diagnostics remain separately reported. Test source was compiled and
the named tests run, not claimed whole-repository lint-clean.

Exact tested ELF SHA-256:
`fe7d19d733fdb18b73247fff89b5064fe75bde651fcfe1721cfc7e140e4f0284`.
Focused result SHA-256:
`37488d443b934179a03f98feb63004c0785f7f057516844172ce940bfed62fe3`.
Changed-span lint result SHA-256:
`c3dcfa8913780a2b64ab58680b51eaabff101073722a74f00e0b0bf18d8d4c43`.

| Node source | SHA-256 |
| --- | --- |
| `src/budget.rs` | `8a9b7009b5966e5e8f3d40629eda7a13160e3f4e010c92b6d740560fdb9a5c32` |
| `src/core.rs` | `70a718c2d790bcbb5d1ef5645d0630205832b2adf224f620a04a24900ff4ed20` |
| `src/graph.rs` | `f3040190a26c696a920c1cae4af9b0cf512f39193f02405b8a71d41b167dcfb2` |
| `src/node.rs` | `cdb1c576dce13aad07f39d7681a1a141538bba89808539aaa3b3228cc7578527` |
| `src/parent.rs` | `efa5abcf152f6788b3c5533584a8d4116ef74b319eee0dcac5eb29917342627a` |
| `src/node/order_tests.rs` | `2de1e87cd3778f85adcf19876ace5cbb9e930954088abb5b9b78640b3015f1c9` |
| `src/node/historical_tests.rs` | `d83fdbae71daab14ade68408628e8a6430e6fd564ed80922a9ae077db1b51ddc` |

## Failed native gate and concrete next experiment

The previous source-26 native run FAILED ingesting candidate 1,361 (ordinal
1,360) on cumulative foreground CPU/wall refusal. Its finer phase and CPU-versus-
wall branch remain unknown. Last completed state: 1,360 vertices, checkpoint
170, sequence 1,530, Ready. Its active marker, partial owner and result remain
preserved without reopen, repair, adoption or retry. Native failed result SHA:
`81870c5e98b49839771a1bda638c2c178450ba23f9b094caf149770d8e19d369`.
No full 3,080-carrier comparison or second cold process followed that failure.

The new ignored test
`node::historical_tests::historical_foreground_diagnostic_prefix_1361_fresh_node`
was initially compiled only. ONE separately authorized execution subsequently
FAILED at candidate 1,233 with a CPU-only cumulative refusal detected at
`GraphOrder`; see [the exact result and subsequent source correction](F04_GRAPH_ORDER_FACTS_V1.md).
The following describes its original scope, not authorization for another run.
It attempts ingesting
ONLY the first 1,361 exact public carriers into an independently owned fresh
node through ordinary admission and bounded checkpoint advancement. It never
opens the failed store or uses historical saved validity. On refusal it prints
ordinal, carrier SHA, original error and any first cooperative failure report.
On success it requires Ready, 1,361 vertices, checkpoint 170, 1,360 executed and
no active job; the fresh HEAD is an observation, not imported pin authority.

The executed outer contract was ONE new capped 1 GiB filesystem; one sequential
UID1000 test child; 3 GiB RAM, no swap, one-CPU quota, four tasks; shared 1,200s
wall and 1,000s child CPU ceilings; no restart, network or listeners; read-only
exact pinned public corpus/parameters/ELF; only that new filesystem writable;
the original separate host reserve and all per-job limits unchanged. No volume
creation or further native dispatch follows from this description. Exact source,
launcher, input, parameter and ELF pins were bound before approval. Failure preserves
the new owner and evidence with no retry. This is materially expanded native
verification, not one of the seventeen minimal source checks.

Passing that prefix would test progress through the former failure point only,
not full 3,080-record acceptance, cold-process replay, two-host operation, wallet
recovery, privacy, practical speed or whole-core/release completion. No native
work/proof generation, mining, valuable assets, live node/seed change, activation,
new timer, dependency, quota lift, pruning or release-default change is included
in this source milestone. Canonical consensus/commitment/wire/economic bytes and
the existing 4,096-vertex/20,000-generation horizons remain unchanged.
