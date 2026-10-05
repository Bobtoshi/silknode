# Two-host native branch and transport recovery v1

This closes a SMALL, same-operator system check, not a consensus redesign,
public peer service, independent operator adoption or production acceptance.
Two real Linux hosts ran the same frozen native executable in separately
isolated, task-owned filesystems. They independently replayed their own pinned
historical 15-position fixture, admitted different existing genuine siblings,
exchanged only public full carriers, converged, admitted the existing merge and
reopened in separate new processes. No peer node store or validity snapshot was
transferred or adopted.

The only Rust changes add an explicitly ignored test module and its cfg(test)
declaration. Existing production interfaces, defaults, consensus/wire/state/
checkpoint bytes, work/proof verification and admission/replay budgets remain
unchanged. The test composes the existing bounded range-framing and ordinary
native Node admission APIs, demonstrating their modular transport boundary.

## Actual journey

1. Both isolated host phases started concurrently from independently pinned,
   authenticated copies of the original 15-position operator history. A admitted
   the saved first sibling; B admitted the original saved second sibling. Each
   reached checkpoint 2 with a different actual state and order. The public
   carrier inputs had already been mined; this journey mines nothing.
2. B exported its freshly admitted sibling through ordinary Node export. Its
   complete 725-byte response crossed SSH to A. A freshly admitted it, derived
   its own preferred branch and changed its checkpoint-2 state to B's state.
   A then exported its actual two-carrier suffix, not an invented peer snapshot.
3. That 1,449-byte response was also delivered to B as a 1,089-byte prefix. The
   prefix contained the COMPLETE, previously unknown first sibling and only
   part of the following carrier. The range decoder refused the whole response
   before the first ingestion. B's HEAD, 16-position graph and state remained
   unchanged, with no foreground or replay marker. Delivering the complete
   response admitted the missing sibling exactly once and treated the other
   carrier as already known. Both graphs reached 17 positions with byte-identical
   independently derived order and state.
4. A freshly admitted the original saved two-parent merge, exported that actual
   carrier and sent it through SSH to B's ordinary native admission. Both reached
   18 admitted positions and the same checkpoint-2 state and exact order bytes.
5. A and B each reopened in a NEW native process using their own independently
   retained local HEAD pin. Full original history/work/crypto/order/ledger replay
   reproduced their saved state/order bytes. Re-ingesting all 18 exact carriers
   returned AlreadyKnown without changing either local pin or granting credit.

Local HEAD hashes differ because generation histories and local clocks differ;
they are not a shared consensus commitment. The actual state and order bytes,
not peer claims or HEAD equality, are compared across receivers.

This is TRANSPORT truncation and resumed full-byte delivery, not a process kill,
power failure, failed-owner retry or recovery of an interrupted native job. The
existing STOP rules for interrupted admission/replay are not weakened.

## Exact evidence

Frozen executable SHA-256:
`3552053bc9adf5ad4ead85aedcd07ffd5d88f6493e43b4264d8d2421bae26844`.
Both actual hosts used that same executable. Eight one-shot native phases passed:

| Phase | Research-host CPU | Existing-Vega CPU |
| --- | ---: | ---: |
| Independently form sibling branch | 6.211 s | 3.303 s |
| Receive sibling / reject cut then resume | 6.363 s | 3.006 s |
| Admit / receive actual exported merge | 6.466 s | 3.846 s |
| Separate-process cold replay and exact repeats | 7.607 s | 3.460 s |

Aggregate native CPU: 40.262 seconds. Highest native memory: 323.4M as reported;
swap zero. Every phase retained one CPU, 3 GiB maximum RAM, no swap, four tasks,
120-second wall and 100-second CPU ceilings. Foreground vertex/checkpoint caps
remain unchanged. Each receiver had a capped 1 GiB filesystem; host margin was
outside it. No public listener, persistent node service, seed deployment, new
proof, wallet key, spendable asset or new infrastructure was introduced.

Compiler: locked/offline release, one job on the research VPS only,
52.802 service / 52.755 CPU seconds, 476M reported peak, zero swap; compiler
task exception 16. No Mac builds/tests and no unchanged broad history suite.

Final checkpoint:
`30d649c79dd019e9bc2aab051a14faeef58997b0b47ffa9ca077ef796e14c0ed`.
Final original state SHA-256:
`fe34b27c1bbe395ba153470e9525255cfc2cc169f3d46aa60bd9f39fb9276ef0`.
Final original order SHA-256:
`4a96ad7b1620bc4005e6a3aa0805336beaa34ee3c30d621a310d765757a87a4c`.

Retained immutable receipts:

- `two-host-native-build-v1-result.json`, SHA-256
  `8d8a17401361170d22baa702e1c0af66c8bb8268fb606729b28a0fb91b578749`.
- `two-host-native-check-v1-result.json`, SHA-256
  `99926534af8f56a180477f85ee347bcbabc0d9f2d2fe88e2e0c61614a2350210`.

The latter binds both actual host identities, all eight per-phase receipts, the
frozen executable/source hashes, exact sender-output/receiver-input hashes,
different branch states, identical final state/order bytes and unchanged local
cold pins. Every phase intent is CLOSED; no task-UID process or fresh-owner
ACTIVE_JOB/ACTIVE_REPLAY remains. The original 4 GiB research image's size,
allocated blocks, mtime and ctime remain unchanged. Original/failed owners,
unrelated WIP, alpha refs and live services are preserved.

## Reproduction and limits

`node/host_recovery_tests.rs` supplies six explicitly ignored role entry points:
branch; receive-sibling-and-serve; cut-response-refusal-and-resume; merge-and-serve;
receive-merge; cold-replay-and-repeat. Run only the corresponding role on each
separately qualified isolated host, with its own authenticated local pin,
existing public fixture and parameters. The fixture domain and bundle hash are
independently supplied, never taken as authority from a received directory.
The gate flag acknowledges scope; it is NOT runtime qualification or permission
to open an original/failed store. Receipt comparison is read-only and never
replays a completed native phase just to collect another status result.

An arbitrary third-party transport still must frame a complete bounded response
before exposing its carriers, treat all returned carriers as UNVERIFIED and
submit each through ordinary receiver-local admission/reconciliation. A later
semantic native failure can leave earlier admissions durable; this is NOT an
atomic native batch or permission to retry a failed owner.

UNPROVEN: native history above 4,096; sustained/Byzantine network operation;
unattended public P2P discovery/transport; independent third-party participation;
ordinary seed-to-wallet cold recovery; throughput, network anonymity and
whole-system privacy. These small same-operator two-host results cannot supply
the independent honest participant/cohort premise of a separate anonymity design.
