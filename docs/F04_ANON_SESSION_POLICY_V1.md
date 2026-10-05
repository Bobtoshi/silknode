# Closed whole-epoch session and strict input provenance v1

This is opt-in local implementation of the bounded M1-R1 policy prerequisites,
not anonymity acceptance, an active service, a new cryptographic relation or a
release-ready network. Existing consensus, Sapling, HPKE, wire/control encodings,
wallet exposure/recovery rules, legacy defaults and public seed are unchanged.

## Closed client ownership

`silk_f04_client::v1::session` owns one baseline enrollment attempt and the
complete selected UTC epoch: 2,880 rounds of 30 seconds. There is no shorter
duration, externally callable round tick, automatic repair or next-epoch loop.
The blocking owner runs on its enrollment/node thread; its `Rc` custody is not
migrated to a wallet thread. Separately supplied clock and public-view owners
must be bounded and independently qualified; their traits do not prove honesty,
clock accuracy, independence from payment work or adequate runtime resources.

The original enrollment window is `[30q-60,30q-30)`, where `q=2880*epoch`.
Setup failure consumes that invocation. The first eight rounds are cover-only.
An empty volatile one-offer mailbox and two-outcome mailbox are created for each
session. The owner inspects clock/public-view health independently of payment
presence. Each fixed `T-8.125` decision admits before the existing `T-8` barrier;
a missed barrier or unavailable/known-invalid local authority is terminal.
No missing-view genesis fallback, peer cut adoption or selected-cover replacement
is introduced. Fresh observations check health; `Schedule::anchored_round` keeps
the original epoch mapping rather than rebasing deadlines on later wall time.

Offers are consumed at most once from that mailbox after warmup. An offer that
arrives after a decision waits for the next original decision. Existing manifest
signature/local-cut checks still precede real/cover payload selection. An invalid
manifest or unusable supplied view follows the existing quarantine and deferred
`+22` outcome path, not fabricated cover.

`Silent` and `WriteUncertain` terminate the owner at outcome draining. A successor
may already have been admitted at predecessor `+21.875`; the failed predecessor's
`+22` outcome drops that provisional successor before its data slot. Early
successor manifest traffic may exist; zero successor traffic is not claimed.
All remaining decisions are accounted as suppressed, not sent cover. Successful
cover/real outcomes drain normally. Slow local readers can lose outcomes when
their two-entry mailbox is full; they never backpressure the network schedule.
The final `SessionReportV1` is local admission/suppression accounting, not cell
delivery, settlement, validity, anonymity or retry authority.

The session has no journal, scan, approval-recovery or export API. Restart uses a
new empty mailbox and separately selected epoch, with no inherited submission.
`submit_once` is volatile in-memory ownership, not durable/global one-use of an
intent/envelope. A fresh explicit human-authorized export of a recovered intent
into a later session is a separate potentially linkable attempt, subject to all
existing wallet pins and exposed-input exclusions. Old consent/timeouts never
authorize automatic export, reproof, cancellation, unreserve or resubmission.

## Strict honest-A provenance

`SourceOwner::new_strict` selects immutable strict policy before any collection.
`InputCollector::new_strict` and `seal_strict` require all 32 distinct roster
slots to complete actual valid input before the original `+9.5` barrier. The
completion tracker advances only after actual TLS record consumption, framing,
context, outer HPKE, encapsulation uniqueness and deadline validation. Missing,
partial, invalid and duplicate inputs cannot be filled or relabeled as complete.

A private completion capability is minted before source labels are erased and
is bound to exact configuration, manifest and round. An opaque `StrictInputBatch`
transfers it into `SourceRound::new_strict`; the capability is retained for that
round. There is no public capability constructor, cloning/deserialization or
conversion from legacy `InputBatch`, even when a legacy batch contains 32 cells.
The original minimum-eight-plus-fresh-filler path remains separate. B's existing
signed `admitted>=8` check is unchanged: B/public observers cannot attest strict
execution. This is honest-A provenance, not protection against a malicious A or
proof of independent participants.

## Reproducible component evidence and limits

Locked/offline Rust 1.93 release builds and checks ran on the existing research
VPS, not the Mac. Final source bytes are frozen in `m1-qualified-v1/source`.
The final relay ELF SHA-256 is
`c455a3a48261e2d67465becad19636ec09517ac699908523f8b743b6b6893f1b`;
the client ELF is
`399e9241edff4d59bae8d42d3fd65e64d9ad8c8ea9761c7253deddf598547512`.

24 relay tests, 15 client tests and one strict API compile-fail test passed.
Relay qualification was split: the 64MiB temporary fixture passed 22 and properly
refused two pre-existing journal tests at their unchanged 4GiB host-margin guard.
Only those two tests were then run in fresh owned directories on the actual
server filesystem, with 16KiB per-file limits and the original bounded journal
format. Original refusals are preserved; no failed production owner was repaired.
Tests used one CPU, 3GiB memory, no swap, four tasks, 15 CPU seconds and 60 wall
seconds per scope. Compiler scopes used one job, 16 tasks and bounded runtime.
Existing compiler warnings remain; strict lint cleanliness is not claimed.

The actual 32-cell test uses TLS and genuine HPKE, but synthetic admission/context
and clock mapping: it is not independent-cohort or qualified live-round evidence.
The private scheduler seam crosses idle/ready/delayed opaque offers with valid,
absent, rejected and late public-view scripts across the full epoch plan. It
checks identical healthy shape, terminal suppression, deferred failure and the
provisional successor. Fake journal/export fixtures cover pre-admission and
post-consumption crashes, empty later sessions and fresh explicit later exports.
No new Sapling proof, mining, real wallet secret or day-long active session ran.

Qualification receipt `m1-qualified-v1/result.json` SHA-256:
`13c4b17e3d5ef7142def40126c5efc5ab1e0af56ebdf9f3a7da64e8289887f72`.
Journal fixture receipt `m1-journal-regression-v1/result.json` SHA-256:
`43dd4f622b1f4e99d9c572650ce53b27627bec7be6325a769410688d432c52f5`.

Mandatory external prerequisites remain honest A, independently administered B,
at least eight independent continuously active honest plausible senders in the
32-member roster, actual <=500ms clock qualification and bounded public-view/
wallet-worker behaviour under load. Malicious-A isolation/count inflation,
A/B collusion, Sybils/intersection and exact B/producer-to-settlement linkage
remain outside the narrow conditional claim. Whole-system anonymity, full live
session integration, under-load qualification and release readiness are UNPROVEN.
Rejected identity-to-payload designs and unaccepted proof-relation proposals are
not implemented or activated by this source update.
