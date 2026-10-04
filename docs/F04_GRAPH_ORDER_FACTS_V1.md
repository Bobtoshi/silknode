# F0.4 operation-owned chain commitment facts

Later execution of the header-facts correction is recorded separately in
[the history/restart report](F04_NATIVE_HISTORY_RESTART_V1.md). The original
source-slice and preceding execution evidence below remain historical records.

This slice removes duplicate checked reads in graph ordering. It follows a
failed native foreground diagnostic; it does not prove that failure is fixed.

## Observed native failure (2026-10-04)

ONE authorized fresh-node diagnostic attempted the first 1,361 original public
carriers using the reviewed source-28 ELF. It FAILED at ordinal 1,232, candidate
1,233, carrier SHA-256
`0461d4f4a6026c3b5abef8d178784ae4f1e5339ab2917ca7f704d3b206d30dc3`.
The refusal was `Paused("cumulative foreground CPU/wall budget")`.

The first cooperative report identified the active `GraphOrder` boundary:
cumulative process CPU 2.000250328s against the original 2s allowance, wall
2.043431403s against 5s. CPU expired; wall did not. These are cumulative
observations, NOT exclusive ordering cost or proof of a unique cause. They do
not retrospectively attribute the older source-26 candidate-1,361 failure.

The test exited 101 after 746.16s; service runtime 746.205s, CPU 675.446s,
peak memory 731.7 MiB, swap zero. The outer 1,200s wall / 1,000s CPU,
3 GiB/no-swap, one-CPU, four-task limits were not exhausted. The fresh store
and active-job marker remain preserved, without reopen, repair, adoption,
marker clearance or retry. There is no through-1,361, full-3,080 or cold-process
success receipt.

Native result SHA-256:
`b2376ca5480179ad941daed712d5a213ff4b40b6b496fc8ae6ac2cff6f093038`.
Frozen executed ELF SHA-256:
`fe7d19d733fdb18b73247fff89b5064fe75bde651fcfe1721cfc7e140e4f0284`.
Exact execution plan SHA-256:
`3951f82438c97dbc6cc4e415cf285925202ec06dfde1198a2a3861d515b8a609`.

Setup deviations were recorded, not hidden as native retries: the initial
empty-volume helper failed while parsing a loop-device listing after mounting;
a read-only qualification corrected that administrative check without another
format. Formatting discarded the outer image's initial allocated extents, so
full physical preallocation did not remain. The logical 1 GiB image and actual
1,020,702,720-byte filesystem cap remained intact. No live-image extent change
was attempted. A preceding root toolchain probe installed Rust 1.93.0; it did
not rebuild the frozen ELF or change the unprivileged execution toolchain.

## Source mechanism

The existing chain fast path first qualifies the whole graph inventory and
parent topology, then checks every metadata recurrence from the anchor. It
previously reopened parent/work/metadata sources for the final graph commitment
in lexicographic ID order. Hash-like IDs make this different from append order
and can repeatedly displace the one-leaf directory cache. The node adapter also
continued reopening index leaves after owning a fully qualified inventory.

The ordering library now retains compact operation-owned facts during the
successful recurrence walk: ID, checked selected parent, individual work, merge
commitment, blue score and blue work. Only AFTER the entire chain and recurrence
are verified does it sort these facts by ID and encode the unchanged reference
graph commitment fields. The already-verified single ordinary parent equals
that selected parent. Domain, lengths, field ordering and bytes are unchanged.
The reference implementation remains unchanged; forks/multiple roots/merges
still select it under the same budget. Errors never select fallback.

The node `View` resolves IDs through its owned sorted inventory only after the
existing complete index/directory qualification has installed that inventory.
Early incremental sealing without an inventory retains the checked index
lookup. Newly loaded directory entries retain ID binding and membership checks.

No payloads, dynamic merge lists, imported validity, negative failures or
cross-operation answers are cached. The immutable graph borrow and operation
lifetime bound these facts; fresh operations qualify sources again and refuse
new damage. Owned checked bytes are a snapshot, not a guarantee to re-read them
after external filesystem mutation. This still sorts and materializes history,
uses O(N) compact facts within the node's unchanged 4,096-vertex horizon, and is
NOT a paged engine, constant-cost admission or sustainable-history proof.

## Focused VPS evidence

Locked, offline Rust 1.93.0 release library/test compilation succeeded on the
isolated research VPS: 50.561s service, 50.431s CPU, 415.5 MiB peak, no swap.
No compilation or test execution ran on the Mac. One earlier launcher attempt
could not locate `rustc`; no compiler/test ran. The corrected launcher explicitly
selected the already-installed compiler without installing dependencies.

ONE focused test passed in 0.25s (282ms service, 264ms CPU, 6 MiB peak, no swap)
under bounded containment. Its disk-backed synthetic 129-vertex chain spans
three directory leaves with ID order deliberately different from append order.
The complete snapshot equals the unchanged reference; 251 budget-counted source
calls satisfy the test's less-than-387 bound under the original vertex budget.
This is NOT an old/new baseline, all physical I/O count or CPU speedup claim.
The same test checks expired-budget refusal, fresh missing metadata refusal,
diamond fallback parity and staged 130th-vertex parity. It generates no native
work or proofs and does not open either failed native owner.

Test: `graph::tests::graph_order_scoped_chain_facts_match_reference_and_refuse_fresh_damage`.
Tested ELF SHA-256:
`5146adff097b2a907573f75c24cf4e918d57ed24ebf07f1d6b5a669c497141b3`.
Focused stdout SHA-256:
`439fd616ad5b3f8bc5e1b06fd883615f811aa5071022a01b8c29a5439764c84a`.
Focused stderr SHA-256:
`25f79fd869350dff4ce0bb73be79a00f69a180f01c41ccc0a0a0bc8c928bf4ff`.

Production changed-span Clippy passed with zero diagnostics on changed spans;
258 outside-change baseline diagnostics are separately recorded across the two
libraries. This is not whole-repository lint cleanliness. Lint result SHA-256:
`110b4d8d8230cb4e918c904af17c96f4ec25d227f5bc47e924410de8d0dc9915`.
An initial receipt script had a syntax error before any lint execution; only the
corrected script dispatched Clippy once.

| Changed compiled source | SHA-256 |
| --- | --- |
| `silk-f04-node/src/graph.rs` | `81e8172051176f2366a92ef0891011dac5a6dc009c4ae548e54eaa7dae210d3d` |
| `silk-order/src/sg0_budgeted_v1.rs` | `3c637b83d0c37d831e6473c7d9f806e72715c4e2bba41619d93cd8a40a67013b` |

## Subsequent corrected-source prefix: PASS (2026-10-04)

ONE authorized execution of the exact corrected ELF passed the fresh 1,361-prefix
gate through ordinary admission and finite checkpoint advancement: Ready,
1,361 vertices, checkpoint 170, 1,360 executed and no active job. Fresh derived
HEAD: `36d3a066d9bde4f9eb92dfee513e3db1e2c83da0f87b46c5c4a9fafd45d6892d`.
The original 2s CPU/5s wall vertex and 10s checkpoint limits were unchanged.
The outer 1,200s wall/1,000s CPU, 3GiB/no-swap, one-CPU/four-task limits held:
test 652.70s, service 652.754s, CPU 584.663s, peak 753.7 MiB, swap zero.
Its new filesystem was separately owned and capped; neither failed owner was
opened or repaired. Unlike the previous preparation, formatting used nodiscard
and retained physical allocation. No new work or payment proofs were generated.

Prefix result SHA-256:
`ca80e2ae224299b910e191dba1f0c98cb5f870869bccca288461f677cc51f4e5`.
Prefix stdout SHA-256:
`24bcd5869c5227e1b35b7c002f1f3b9cbdbbe31c34f27a4ed04307751ce2de35`.
Prefix stderr SHA-256:
`195e47ff130f1d0d5a74baa849bc43262ec6d3f75a81fa426b58331eb14ae34c`.
Frozen corrected-source plan SHA-256:
`2d2f1ffe3054df79c105fe8c17ae1416bf5275b1a328cf4cb004ba9307c3be5e`.

This passes both former refusal points for this exact original public fixture
and current source. It is not an all-input performance fix, a speed comparison,
full 3,080-carrier acceptance, cold replay or whole-core completion.

## Remaining gate

Full 3,080 ingestion and a separately gated cold process are the next bounded
native acceptance check; prefix success does not grant an unlimited retry loop.
The subsequent full attempt FAILED at candidate2,449 with a CPU-only cumulative
refusal detected at GraphOrder; cold replay did not start. See
[the exact result and next directory-read correction](F04_GRAPH_HEADER_FACTS_V1.md).
Full 3,080-carrier acceptance/cold replay, sustainable restart/reorg, isolated
two-host disconnect/concurrent-branch recovery and whole-system privacy remain
unmet integrated gates. No quota/horizon lift, consensus change, release-default
activation, mining, valuable asset or live node/seed change is included.
