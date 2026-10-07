# Bounded local generation replay directory

Clean sessions can publish clock-only generations without adding graph vertices.
Generation history therefore has a separate lifetime limit from graph size.
This change replaces the fixed 313-address replay directory with bounded-fanout
pages and adds an explicit, finite local generation profile. It is not pruning,
a consensus upgrade, an automatic capacity increase or a production guarantee.

## Explicit local choice; unchanged defaults

`HistoryLimitsV1::REFERENCE` and `for_vertices` still select 20,000 generations.
Callers can independently opt into a different finite count:

```rust
let limits = HistoryLimitsV1::REFERENCE.with_generations(40_000)?;
```

`with_generations` checks that the selected graph's complete linear history
fits and refuses counts above 1,048,576. This upper bound closes the directory
geometry; it is not measured native capacity. Existing explicit Node creation
and independently pinned reopen methods carry the profile. No CLI, testnet,
genesis, mining or release default changes.

The choice is not serialized or inferred from a peer, saved counter, cursor or
validity flag. Other graph, object, disk, effect, cache and CPU/wall/process
limits remain in force. Generation or storage exhaustion still pauses locally;
selecting more generations does not reserve space or qualify a runtime.

## Fresh full-data replay

Original `SNF04HD1` headers and `SNF04RP2` leaves retain their exact encodings.
The new content-addressed `SNF04RD1` auxiliary pages contain a domain, aligned
child ordinal, level, exact child count, reserved zero bytes and up to 64 hashes.
Each payload is at most 2,104 bytes. Consensus, vertex, genesis, order, state,
delta and checkpoint bytes are unchanged.

Every cold reopen rebuilds from the independently pinned HEAD and authenticates
the complete backward header lineage. Descending construction holds at most
three pending 64-address groups, independent of total journal length. A fresh
in-memory root then directs forward traversal through the original leaves and
headers; the ordinary full semantic replay is still required. No saved root or
completed cursor substitutes for verification.

At the maximum selected count, 16,384 leaves require at most three directory
levels. Construction and traversal remain O(N), with bounded resident address
groups and one directory payload read at a time. Completed pages deduplicate,
but retained original records and changing auxiliary paths still consume disk.
Failed and unreachable objects remain charged. No history is deleted.

Missing, corrupt, foreign or reordered auxiliary pages stop replay without
advancing record authority, switching HEAD to PREVIOUS or renewing an
interrupted attempt. A zero-based intact header sequence equal to the selected
generation count is already over the limit: public Node reopen now refuses
that case before creating a replay/job marker or writing store bytes. Header
counts can refuse local resources; they never establish a valid lineage.

## Verification scope and limits

Prior component verification passed 15 focused synthetic checks, including
complete byte traversal of an actual contiguous 20,033-header journal,
reference-profile refusal, exact terminal HEAD, fresh rebuild/deduplication,
directory geometry, malformed/foreign/missing pages and interrupted-write
refusals. Synthetic headers and geometry digests confer no work or ledger credit.

The durable large-fixture check initially reached a 120-second runner wall
limit. A separately bounded continuation of only unfinished checks completed
the large case in about 153 seconds under a 600-second wall, 120-second CPU,
1 GiB/no-swap envelope. This is fixture/check evidence, not throughput or
production recovery performance.

One saved genuine eight-carrier cold replay under the 40,000 profile preserved
the exact independently pinned HEAD, checkpoint and state, all original bytes
and closed replay/job markers. Integrated-source verification separately
passed a public-API boundary check using one deliberately synthetic over-count
header, plus the focused build and non-test check. That boundary fixture is not
a valid 20,001-generation history. Component checks were retained evidence,
not rerun or relabelled as integrated-source executions.

The accepted runtime Rust files are exported unchanged. No build or test was
repeated for this public source export. The prior builds used an offline,
locked F0.4-focused harness, not a full-workspace or whole-distribution check.
Native tests need separately bounded execution, canonical public parameters and
an independently pinned disposable store copy; they are ignored by default.

This does not establish a native graph above 4,096 vertices, a native semantic
Node workload above 20,000 generations, indefinite retention, pruning,
distributed consensus, anonymity, production economics or release readiness.
The existing alpha tag and nonproduction warnings remain unchanged.
