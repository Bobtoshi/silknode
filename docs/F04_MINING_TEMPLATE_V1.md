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
## Producer handoff to a separate miner

`ProducerInboxV1::take_next` (relay crate) consumes the volatile released offer.
After leaving the relay lease, `LocalOfferV1::prepare_current` consumes that
offer in the separate node owner. For a real offer it returns
`PreparedV1::Template(MiningTemplate)` using the node's selected parents,
fresh ordinary timestamp, reward binding and unchanged foreground budget.
No nonce is evaluated in this call; the durable preparation job is closed
before the immutable template leaves the owner. `PreparedV1::NoPayment`
creates neither template nor job. Errors consume the offer, never requeue it.
The original synchronous mining API and all release defaults are unchanged.

The existing `encode_local` / `decode_local` pair can move exact body bytes
between explicitly trusted local processes. It does not authenticate that a
relay executed, create a public payment endpoint, or recover a dropped offer.
Any subsequent external nonce evaluation requires separate enforced CPU,
wall, memory and storage limits. A resulting ordinary `Candidate` still goes
through `Node::ingest`; a template gives no proof, spentness, admission,
canonical-effect or wallet-settlement authority. An owned template may outlive
its preparing node; stale parents and claims remain the receiver's decision.

The 5 October 2026 Linux qualification used a NEW authenticated copy of the existing
15-vertex public-payment fixture, with independently retained head
`459e35c58616f47eda88cc44443ad380b70be7515d3bf5fe6dbb9336256111a6`.
It prepared 1-, 3- and 32-envelope templates, checking exact body order,
reward fields, unchanged head/state/carriers, absence of active jobs, cover
and foreign no-job refusals, and successful same-process cold reopen.
Repeated saved envelopes test maximum framing, **not** independent valid
payments or spendability. No new work, proofs or wallet keys were generated.
The consumed-offer compile-fail check and four existing focused framing checks
also passed. This is not a fresh relay journey, settlement, independent
operator test, crash test, native history beyond4096, or anonymity acceptance.

Native runtime: one CPU, 39 CPU seconds /120 wall seconds, 3 GiB RAM,
no swap, four tasks, no public listeners, only a fresh directory on the
existing capped1-GiB task filesystem writable. It used 10.459 CPU seconds,
10.672 wall seconds and325 MiB peak memory. Build/doc/framing/native work
used83.455 CPU seconds total, including the retained20-ms sandbox launch
refusal. That original pre-exec namespace error changed no store; only the
mount configuration was corrected, without repeating the passed checks.
Receipt: `/var/tmp/silknode-replay-pages-evidence-v1/offer-prepare-v1/result.json`,
SHA-256 `ddcad44d7b7700bcb93509180afa1c6d8b309cf7f08fa6df830bcafd1a3f7f11`.
The ignored gate is
`offer::v1::native_tests::saved_public_payment_offer_prepares_without_work_or_admission`;
its explicit fixture environment is documented in the test source. Use only
a new authenticated public-input copy with its own retained pin and resource
containment; never reopen or repair a failed owner to rerun a qualification.

## Local jobs across process boundaries

`MiningTemplate::encode_local` consumes a prepared input and returns its bytes
and SHA-256 pin for separate local retention. `decode_local` requires admitted
genesis and the independently retained pin, not a pin supplied by the input.
This opt-in private codec is not a consensus carriage, public endpoint, stable
cross-language ABI, signature, relay provenance or permission to mine.

The exact frame is `SNF04WT1`, four version/reserved bytes `01 00 00 00`,
big-endian header length592 and body length, then the unchanged592-byte header
and existing canonical body. Total size is632..89912 bytes, including at most
32 envelopes. Lengths/context/body bindings and pin are checked before any VM
allocation. The body retains its existing public Sapling proofs and encrypted
recovery data; there are no wallet keys, new proofs, work proof or node caches.
The worker derives the existing work key from the **claimed** header seed.
Correct framing and a matching pin do not authenticate parents, source, DAA,
current time, payment validity or canonical effects. Only ordinary ingress can
establish those; a forged but pinned job may waste a miner's resources.

Two separately invoked Linux processes on 5 October 2026 qualified this boundary.
A fresh authenticated15-vertex owner prepared empty,1- and32-envelope jobs,
closed every job and left its head/state/graph and old public bytes unchanged.
The empty job used explicit ordinary mining preparation, not a cover offer.
A second process imported only13 public job/genesis/reference files, read-only,
with the node store and Sapling parameter paths hidden. All three job sizes
(632,3422,89912) round-tripped exactly. Its original work-input bytes matched
the preparer's for nonces0,7 and `u64::MAX`, without evaluating those nonces,
creating a VM or generating work/proofs/keys. Wrong pins, malformed lengths,
reserved bytes, changed contexts/body bindings, truncation and oversize refused.
The deliberate accepted DAA-claim mutation shows that decoding is **not**
receiver authentication. Repeated saved envelopes test framing, not new valid
payments. Both processes used one CPU,3 GiB RAM/no swap/four tasks/no public
listeners; preparation was capped39 CPU/120 wall seconds with only a fresh
capped-volume directory writable, import5 CPU/30 wall seconds with no writable
node path. Preparation used 5.499 CPU/5.757 wall seconds and324.3 MiB peak memory;
import used67ms CPU/82ms wall and9 MiB peak. This is not nonce-search,
settlement, independent-operator, crash, anonymity or whole-core acceptance.

Native receipt:
`/var/tmp/silknode-replay-pages-evidence-v1/local-template-release-v1/result.json`,
SHA-256 `093c523c88278f9591277cbb6a542dc01f3d791ef9f2f07a5d064629d72c4782`.
The exact final native ELF SHA-256 is
`bb2e38e8ee95979e9a5faa0d4de63ed470ff0ddfaf36e712c9b0e3bb2455e3bf`.
Original two-process receipts remain at `local-template-v1/result.json`, SHA-256
`ffb1a7a44b3423d878dd586c418eedd9658c21458f0fa43033b90047f9f0b483`.
A single doc-line correction distinguished existing body proof bytes from new
proof generation. Its rebuild produced a different ELF, so that earlier runtime
acceptance was not transferred: both final-binary phases used another fresh
public-history copy. The no-transfer receipt is `local-template-v1/final-doc-result.json`,
SHA-256 `90066b48dc47dc8c5e058109374155926716f6f1c57f0af047061465785aa32f`.
The final receipt also corrects the earlier top-level `new_vm=0` field: zero VM
allocation applies only to the importer. The preparing node re-verifies existing
history with its native work engine, included in the reported CPU/RAM totals;
it performs no new mining. No earlier receipt was overwritten or erased.
