# Bounded native private-pipe synchronization v1

This is an opt-in native node transport and ordinary operator integration, not
another manual per-range fixture. `pipe-serve` automatically serves a fixed,
locally replayed inventory; `pipe-sync` requests every source position from zero,
frames each complete response and uses ordinary live admission/reconciliation.
The actual two-host check used existing independently authenticated SSH pipes,
not public listeners, peer-store transfers or new mining.

## Interface and trust boundary

The existing private `silk-f04-local` commands, required genesis/domain/parameter
inputs and independently retained own HEAD remain authoritative. Two opt-in
commands are added:

- `pipe-serve`: binary framed stdin/stdout; fixed local admission-order inventory,
  at most 32 full carriers per response; no submission route or source mutation.
- `pipe-sync --max-steps 1..512`: automatic source-zero catch-up with ordinary
  per-carrier work/proof/parent/clock verification and bounded reconciliation.

Pipe status and error reports use stderr only. Pipe commands never flush the
local clock. Retain a successful or still-healthy failure report's OWN HEAD
outside received inputs. A source HEAD is never transmitted/adopted. Mandatory
cold opening still appends ordinary closed replay journals: this is not a
filesystem-read-only reopen or byte-identical entire-directory claim.

The new private-pipe schema `SNF04PS1` binds the already selected local genesis
domain and exact bundle hash, followed by a bounded advertised count. It changes
none of the existing public testnet/TLS, consensus, carrier, state, checkpoint or
commitment bytes. Four-byte BE outer frames contain the existing complete range
framing. Source requests must progress from zero in this one connection; a
caller-supplied old cursor is not accepted. Every duplicate is locally compared.

The operator must supply independently authenticated duplex transport and a
hard whole-process/aggregate timer. Pipe reads/writes can block; this module
alone is not OS containment or an Internet-facing authenticated daemon. Received
counts only constrain requests; they never establish graph prefix equality,
source completeness, ordering, work, a checkpoint or state convergence. Success
means the advertised source bytes were ordinarily processed. A receiver with
additional branches can have a different count/state. Inspect locally derived
state separately; the receipt explicitly does not claim convergence.

Whole bounded response framing completes before its first admission. A cut
response gives no admission from that response. Earlier COMPLETE responses can
remain durable after later loss. A later semantic/native failure can retain
earlier admissions; this is not atomic batch acceptance. No automatic retry,
failed-owner reopen/recovery, resumed native allowance or snapshot import exists.
Only a separately qualified, still-healthy receiver with an independently retained
own pin may start another explicit process. Native interruption remains STOP.

## Explicit local history profile

All local operator commands now accept optional `--history-limit N`: a canonical
multiple of eight in 8..8192. Omission remains the unchanged 4096 reference.
One operator-selected value binds node create/pinned reopening, public inventory
opening, received range framing and position syntax. It must be selected again
for each process; no saved/peer flag enlarges it. Generation, storage, worker and
native budgets remain unchanged. Existing network/release defaults do not change.
Native history above 4096 is still UNPROVEN.

## Actual native check

The same frozen production executable ran on two real isolated Linux hosts,
each with a NEW separately owned authenticated 15-position historical fixture.
A explicitly chose 8192; B omitted the option and reported 4096. Both admitted a
different existing genuine sibling and reached DIFFERENT checkpoint-2 states.
The independently pinned fixture supplies public data only, not wallet keys.

1. B's native source and A's native receiver communicated automatically through
   duplex SSH. A checked 15 exact duplicates, admitted B's sibling and genuinely
   reorganised to its state, reaching 17 positions.
2. A's actual 17-position response was delivered to B without its final 32 bytes.
   The complete previously unknown sibling preceded the cut, while the last
   previously known carrier was partial. B exited with transport failure before
   ANY response admission: its own HEAD/count/state and every preexisting file
   remained unchanged. Mandatory cold replay added only closed audit evidence.
3. New source/receiver processes then completed automatic catch-up: B checked
   16 duplicates and admitted exactly one missing sibling, reaching 17.
4. A ordinarily admitted the EXISTING genuine two-parent merge. A fresh native
   source and B receiver exchanged the full inventory automatically; B checked
   17 duplicates and admitted only the merge, reaching 18.
5. Separate fresh-process source B / receiver A full retained reopening and
   exchange reproduced each own pinned state. All 18 returned AlreadyKnown;
   both own pins and every preexisting file remained unchanged. Independently
   verified final original state and order object BYTES match across hosts.

This is RESPONSE truncation, not a native process kill, power loss or recovery of
a failed admission/replay owner. Sources cold-opened their own local stores;
neither received/adopted the other's store. Different local HEADs are expected.
Only public request/response bytes crossed SSH; Mac orchestration forwarded those
bytes and read receipts. All compilation/native verification ran on the VPSes.

Frozen production ELF SHA-256:
`caec8050fff2634e996fade60a1e2e1ea45eaf9a1df09f345ef98ed014153636`.
Seventeen bounded native phases, including a too-small-profile preflight refusal,
used 77.632 aggregate CPU seconds. Highest native memory was 325.2M as reported.
Each phase: one CPU, 39 CPU seconds, 120 wall seconds, 3 GiB RAM, swap zero,
TasksMax4, only its NEW owner writable within an existing capped 1 GiB volume.
Existing foreground vertex/checkpoint limits are unchanged. No task process or
ACTIVE_JOB/ACTIVE_REPLAY/outer phase intent remains. Original 4 GiB image metadata
and original/failed owners are unchanged; evidence/WIP and release refs remain.

Final checkpoint:
`30d649c79dd019e9bc2aab051a14faeef58997b0b47ffa9ca077ef796e14c0ed`.
Original state SHA-256:
`fe34b27c1bbe395ba153470e9525255cfc2cc169f3d46aa60bd9f39fb9276ef0`.
Original order SHA-256:
`4a96ad7b1620bc4005e6a3aa0805336beaa34ee3c30d621a310d765757a87a4c`.

Retained exact build receipt `native-pipe-build-v1-result.json` SHA-256:
`dd8f3c5b528f29c3d7ab462aa5b14f064a09f8401aa6655a300f855fc782e9de`.
Native closure `native-pipe-check-v1-result.json` SHA-256:
`4ca51e8a628074b34397a908a02ac3a249a12f542646b63598ce18fb563d9825`.
The latter binds all 17 native role receipts, journals, source/profile identities,
request/response hashes, actual unknown-complete-carrier cut, admissions/duplicates,
divergent branches, final byte parity, own pins and closure checks.

Two administrative collection assertions initially misclassified SUCCESSFUL
native operations: admission reports legitimately said NeedsReconcile, and
source cold opening legitimately added closed replay journals. Original false
collector receipts remain unchanged. Narrow read-only qualification bound native
exit0, exact own pin/status/record/object bytes and absence of active jobs; no
native operation was rerun or failed owner repaired. The later collector requires
preservation of every preexisting byte, allowing ordinary new replay journals.

Seven focused component checks passed: five affected ordinary CLI syntax/file/
pre-open-refusal cases and two new pipe framing/context/profile cases. These are
small component checks, not seven independent security/privacy acceptances.
Locked/offline release compilation used one job / Tasks16 / 3 GiB / no swap;
three compiler phases used 78.986 CPU seconds. Existing compiler warnings and
new missing-field-documentation warnings are not a strict clean-lint result.
No unchanged large-history, maturity, mining or proof-generation suite was rerun.

UNPROVEN: native >4096; independent operators/cohort; public P2P/discovery and
sustained/Byzantine operation; process-crash recovery; ordinary wallet cold
reconstruction; throughput, timing under real payment load, network anonymity,
whole-system privacy and release readiness. No seed/core service deployment,
public port, new wallet secret, spendable asset, mining or proof generation.
