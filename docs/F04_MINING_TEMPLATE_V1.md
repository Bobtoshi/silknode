# F0.4 bounded mining-template interface

This is an additive, explicit private/valueless Rust interface. It is not a
network endpoint, default activation, stable cross-language ABI, mining pool,
phone performance claim or permission to bypass wallet/relay policy.

`Node::prepare_mining_current` prepares an owned `MiningTemplate` using the
ordinary current-time policy and fresh parent/source/DAA derivation. Preparation
uses the unchanged five-second wall/two-second process-CPU foreground budget,
native deadline and durable attempt/terminal closure. It does not search nonces,
admit a vertex or change the complete graph/checkpoint head. Its local attempt
marker is distinct from the existing synchronous mining marker.

After preparation closes, `WorkEngine::evaluate_nonce(&template, nonce)` performs
exactly one genuine pinned interpreted-light RandomX evaluation. The work engine
belongs to the miner, not the node. An unsuccessful nonce returns `None` and has
no node-store effect; a successful one returns an **unadmitted** full `Candidate`.
Header/body claims, work input, target, proof framing and vertex-ID commitments
are the existing F0.4 bytes. The template is immutable and does not carry
receiver validity or admission authority.

The caller must enforce its own aggregate CPU, wall, memory and process limits.
One native hash is not cooperatively interruptible. This interface deliberately
does not pretend that a per-call hash count is a hard wall/memory bound. An
independent worker/process can be terminated without leaving an active node
search job, because template preparation has already closed. The bounded fixture
also checks that the node head, vertex count and absence of `ACTIVE_JOB` remain
unchanged after each nonce evaluation.

```rust,ignore
use silk_f04_node::carriage::WorkEngine;

// Explicit valueless caller inputs and an externally bounded worker only.
let template = node.prepare_mining_current(body, owner, reward_nonce, parents)?;
let mut miner = WorkEngine::default();
for nonce in 0..64 {
    if let Some(candidate) = miner.evaluate_nonce(&template, nonce)? {
        // Finding work is not admission. In a separate worker, pass the exact
        // candidate.encode() bytes back to the ordinary receiving node.
        node.ingest(&candidate.encode(), &parameters)?;
        break;
    }
}
```

The receiving node independently checks current local time, canonical framing,
parent membership/incomparability, source/DAA/key derivation, genuine work and
ordinary body validity. It does not import the miner's caches or preparation
facts. Templates may become stale; no retry or acceptance guarantee follows.
Existing `mine_current`/`mine_candidate` retain their original cumulative search
budget and synchronous semantics; they are not silently granted a larger cap.

## Why this boundary is needed

An initial isolated fork fixture was killed by the node's native foreground
deadline during its first synchronous mining call. No new vertex was saved.
The original failed owners and failure evidence remain preserved, not repaired
or reopened. A separate no-mining diagnostic measured parent preparation at
0.007600944 seconds, cold verification of one existing work record at
1.399757482 seconds, and warm verification at 0.27537643 seconds, with required
individual work 5. These are one named-lab observations, not a speed guarantee.

The source path was `Node::mine_inner` → `Core::mine` → `WorkEngine::mine`.
Repeated nonce search consumed the same two-second process-CPU allowance as
single-vertex reception. Ordering is not performed by that mining path; the
parent worker uses blocking handoff rather than a busy spin. Cold replay returns
the same owning work engine, without a per-mine VM reset. The failed run did not
record its exact nonce count, so that count is not retrospectively claimed.

The correction separates producer search from receiver verification. It does
not increase difficulty allowances, change the work backend, weaken validation,
change consensus/economic/wire bytes or turn mined results into trusted state.

## Verification and reproduction boundaries

The pure `carriage::mining_tests` checks compare exact candidate bytes with the
previous construction, reject above-target synthetic hashes and unmatched
header/body/facts, and cover the maximum nonce representation. Synthetic hashes
in those checks are never admitted and are not genuine-work evidence.

```sh
cargo test --manifest-path prototype/Cargo.toml --locked --offline --release \
  -p silk-f04-node --lib carriage::mining_tests -- --test-threads=1
```

The ignored native fork tests require an externally isolated, authenticated
historical fixture and canonical Sapling parameters. They must not be run
against an operator's node store or inferred to pass merely because they build.
Their intended boundary is two new empty-body work vertices, one reused original
genuine sibling, opposite ingress, executed-checkpoint reorganisation, independent
execution parity, unchanged-head duplicate ingress and a second-process cold
replay. Native acceptance is a separate retained result, not established by this
document or the pure tests alone. Larger history, independently administered
hosts, new private transfers/wallet recovery and whole-core acceptance remain
separate gates.

### Retained bounded result

The changed interface genuinely mined one empty-body sibling in six evaluations
(2.888659590 seconds) and one two-parent merge in two evaluations
(1.811598845 seconds). Two subsequent fixture mistakes were corrected explicitly:
canonical sorting of merge parents and use of the public materialized-state view.
Every failed owner/output remains preserved. Only authenticated full public
carriers were reused in new copies; failed node stores were never reopened.

The final fresh-copy run passed both ignored tests in two distinct OS-process
lifetimes: 18 admitted genuine vertices, opposite sibling ingress, executed
checkpoint rollback/convergence, full independent execution/state/order parity,
same-process and second-process cold replay, and unchanged-head exact repeats.
It also rejects forged work and unmatched header facts through ordinary ingress.
It mined nothing further and generated no new payment proofs. The final run
was 41.087307 seconds; the original failure, no-mining diagnostic and two partial
changed-path runs plus that final run totalled 96.228285 seconds within the
original 120-second ceiling. The final service reported 589M peak memory, zero
swap, under the unchanged 3GB limit; the earlier partial runs stayed below it.

Ten focused template/clock/cumulative-worker-budget checks passed, plus the
existing durable-job closure test. That latter test initially failed before any
store operation because its generic `/tmp` was read-only in the sandbox; an
explicit owned writable temporary directory corrected only the test harness.
The failure remains retained. Changed production spans had zero lint diagnostics
(156 outside-span baseline warnings are not claimed fixed).

Retained receipt names: `external-miner-fork-v4-result.json`,
`external-miner-focused-v3-result.json`, `external-miner-job-closure-v4-result.json`
and `scoped-external-miner-lint-v2.json`. The production Rust bytes are identical
across the latter lint/focused/mining results and final fork replay; only fixture
corrections changed between builds. These receipts and the historical fixture
are separate evidence, not automatically available from a source-only clone.
This is bounded local lab evidence, not independent reproduction or whole-core,
larger-history, payment/wallet, two-host network or release acceptance.
