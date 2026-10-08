# Optional IM3 three-relay source slice

IM3 is private, valueless research, published here as default-off source. It
does not activate anonymous networking, replace the ordinary relay path or
change payment/consensus bytes, public testnet defaults or the alpha tag.

## Source map and dependency closure

Paths below are relative to `prototype/crates/`.

| Component | Source |
| --- | --- |
| Profile-bound three-layer transport | `silk-f04-relay/src/aip2_im3.rs` |
| Experimental fixed schedule | `silk-f04-relay/src/im3_schedule.rs` |
| Complete middle/exit verification, manifest and signed control chain | `silk-f04-relay/src/im3_gate.rs`, `im3_gate/{stage,receive,exit,control,cycle,exit_cycle,manifest_cycle,authorizer,producer}.rs` |
| Original ingress and authenticated cancellation | `silk-f04-relay/src/im3_gate/ingress.rs` and original receive/exit owners |
| Mandatory runner ports and durable successive-round fence | `silk-f04-relay/src/im3_gate/{runner,sequence}.rs`, `aip2_claim.rs` |
| One-shot B→C proof preparation | `silk-f04-relay/src/im3_gate/client.rs` |
| Original wallet/client TLS integration | `silk-f04-client/src/v1/im3_lab.rs` |
| Earlier R2 dispatch/collection prerequisites | `silk-f04-client/src/v1/r2_lab.rs`, `silk-f04-relay/src/input/r2_lab.rs`, transport/source/runtime/negotiation/TLS adapters |
| Explicit functional orchestration and cold-recovery selectors | Client `v1/im3_lab/tests.rs`, relay `im3_gate/tests/`, wallet `journal/intents/canonical/runtime_tests/live_relay.rs` |

Relay preparation is Unix-only and gated by `aip2-preparation`. Functional
runtime constructors also require `functional-lab`. Client integration requires
`r2-functional-lab`, which explicitly enables both relay research features.
All defaults stay empty. Examples remain explicit lab targets, not daemons.

The client consumes an ordinary already-exposed wallet offer, receives M on its
original A link, validates the actual selected cut and freezes its common claim
before dispatching B then C once. A/C/B retain original links and absolute
deadlines. Full batches, distinct nullifiers and native proof verification
precede disclosure and ordinary producer release. Counts, saved receipts and
caller booleans are not authority. Failed owners quarantine links; no reconnect,
replacement proof or partial-train release is introduced.

`Im3RoundRunner::run_round` admits a durable sequence claim before handing out
nonconstructible scoped `Im3RoundPorts`. Borrowed role owners cannot escape a
terminal transition. Success requires B's completed release and cleanup, not
node settlement. An interrupted consumed scope is never resumed; cold reopen
requires independently selected latest pins and preserves original refusals.
Native clock/CPU limits are not reset on a new proof phase. External clock
qualification, pin honesty, worker containment and peer closure are obligations,
not consequences of Rust types. This is not a production operational profile.

## Public packaging and reproduction limits

The runtime/client sources are taken from committed objects at frozen source
`50bb496fb794f37193bcbd4ef1c051473c3c5c64`, with no private Git ancestry imported.
The public commit is a descendant only of the preceding public source.
Original execution acceptance belongs to the reviewed private sources/fixtures;
no new build, test, native run or proof was executed for this export.

The two-client harness uses the completed
`bcb353296e36aaeaa0d4fa16257d48f3d0aefcec` version rather than later
unfinished fault orchestration. Minimal public curation removes the private
challenge-validation function and replaces private absolute Node paths with
explicit `SILK_IM3_NODE_BINARY` input. Other fixture/proof-helper paths are also
explicit environment inputs; there are no implicit private host paths.
This curated harness has not been executed as a public package. The source's
`#[ignore]` annotations and input reads describe prerequisites, not shipped data.

Private readiness/start-gate and fault-supervisor fixes through the frozen
source are not bundled. In particular, this package does not include the late
Missing-arm preparation controller or an accepted hidden-assignment fault run.
No new public harness was invented to fill that gap.

Operational supervisors, proof helpers, challenge inputs, honest credentials,
private C keys, evaluator truth/reveal maps, toxic setup/proving files, raw
private receipts and binaries are excluded. Public test seeds and certificate
generators remain known toy material only. A separately supplied verifier pin
authenticates bytes; it does not establish trusted-setup soundness. The earlier
R2 components remain vulnerable to colluding-relay source linking and must not
be represented as an anonymous operational path.

## What the evidence means

See [research status](../STATUS.md) for three separate demonstration scopes.
The two-client record `bcb3532` describes two fresh timed clients, not 32 fresh
timed honest users; the other thirty members were prepared beforehand. Its
three matching offers are not settlement. The earlier joined client/recovery
demonstration supplies separate fresh-node settlement and cold wallet evidence.

The independently reviewed record
`556d52bf9133310d43d75006586fa7f817ab866f` contains one frozen hidden-assignment
source-link prediction. It rejected one timing/order hypothesis in that trial.
It does not prove system-wide anonymity, negligible advantage, independent
custody, universal timing or release readiness. The latest fault attempts
failed before the intended honest fault path and remain incomplete, not privacy
successes. Private evidence and evaluator inputs are deliberately not public
reproduction dependencies. No security audit or full public reproducibility
claim follows from source disclosure review.
