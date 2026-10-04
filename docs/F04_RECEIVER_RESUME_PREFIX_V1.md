# F0.4 receiver-derived public-history resume prefix

`PublicHistoryV1::admitted_prefix(&Node)` derives the first missing manifest
position from this receiver's own admitted membership and exact original
carrier bytes. It does not use a saved cursor, peer count, `Node::vertex_count`,
source HEAD, claimed checkpoint or imported validity. This is an additive
read-only primitive for independently written transport modules, not an
activated transport or an automatic catch-up service.

## Implemented boundary

The entire scan shares one unchanged checkpoint job allowance. The receiver
must be healthy, idle and Ready with neither ACTIVE_JOB nor ACTIVE_REPLAY.
Genesis domain and original bundle must match. Each present ID is checked
through the existing retained index/directory path and its original source
object is freshly read, authenticated, framed and hashed against the pinned
manifest row. An absent admitted ID returns its position. A present ID with
different bytes is an error, not a missing position. I/O damage or exhausted
scope propagates as refusal, never a guessed zero or cached prefix.

No persistent cursor, positive/negative validity cache, body import, native
admission, marker write/clearance or ledger mutation occurs. The result is only
a request-planning hint for this selected inventory. Admitted red evidence is
still retained evidence; membership does not imply ledger execution. A complete
prefix does not establish the preferred branch, source checkpoint, final state
or convergence, and does not exclude extra receiver records.

Callers request a bounded window at the derived position, use
`decode_range(bytes, start, count)` to bind the complete response, and pass every
carrier through ordinary `Node::ingest` and reconciliation. No budget renewal
or retry of a refused/unfinished native owner is authorised by this query.
32-carrier and 4096-history bounds, consensus/commitment bytes, dependencies,
privacy/economic profiles and release defaults remain unchanged.

## Focused research-VPS evidence

Locked/offline Rust 1.93 release compilation passed in 42.163s service time,
42.065s CPU, reported 412.9M peak, swap zero. Five-file formatting ran only on
the VPS. Changed-production-span Clippy passed with zero new findings; 156
outside-span baseline diagnostics remain separate.

Three new exact cases passed, using the exact-source frozen ELF below:

- Synthetic context/fences/expired-scope case: nonempty and empty manifests
  derive zero on an empty receiver; both refuse expired scope and synthetic
  ACTIVE_JOB/ACTIVE_REPLAY fences; a different genesis refuses. Synthetic
  markers were created and removed only in that disposable synthetic fixture.
  Service 104ms, CPU 81ms, reported peak 8.5M, swap zero.
- Four genuine existing historical carriers: a truncated bound response admits
  nothing; ordinary native admission/reconciliation yields prefix 4 against
  the 3080-row inventory. Swapping source rows 1 and 8 yields prefix 1 despite
  the receiver retaining four IDs. A known ID with changed carrier hash refuses;
  the query leaves receiving HEAD unchanged. Service 2.681s, CPU 2.611s,
  reported peak 354.6M, swap zero.
- A separate OS process opens only that successful four-carrier receiver with
  its independently frozen receiving HEAD. It derives prefix 4 without previous
  recovery. After a warm query, one exact original source object is moved to
  recoverable quarantine; the next query refuses rather than using cached
  success. HEAD/count remain unchanged and no operation markers are written.
  Service 2.260s, CPU 2.224s, reported peak 322.8M, swap zero.

Compiler-only Tasks16 remained 3GiB/noSwap/one CPU/20min/1000CPU. Each test
remained Tasks4/3GiB/noSwap/one CPU/300wall/200CPU, with no network/capabilities,
strict read-only system/home, and only its owned tmpfs fixture writable. No new
mining or proof generation occurred: the four original public carriers underwent
ordinary receiver verification. No old failed/successful history owner was
reopened, repaired or adopted; the successful full3080/cold run was not repeated.
No Mac build, test, formatting or proof computation occurred.

Receiving HEAD before controlled fixture damage:
`a11034c9a3af08c198a43522c45364a9e4b4ee440692a019308488731735547d`.
The expected pin was frozen outside the tested store, from only the successful
fresh process output. The damaged new fixture and quarantined object are kept;
no subsequent repair/reopen is part of this evidence. Closeout found UID1000
processes reaped, no fixture operation markers, protected original image
metadata unchanged and only SSH listeners.

## Exact-source custody

Tested ELF SHA-256:
`8af8ba37c5695e11b8844ddd6b25a387885ee0d9f021a990678efd35d1b2edef`.
Changed-source SHA-256:

- `graph.rs`: `6905af50e0801925d695c1853856535e7dfb5bb79212c919d61b1e2d30e568a8`.
- `history.rs`: `7a480dac1262e07c9c122367d99602b8371ac8078a1154a59ce8e44f569c1f40`.
- `history/tests.rs`: `8cd6cf4b948b4da633ea4bdf19ed36d972645aadef64d0d4f013d274f346b572`.
- `node.rs`: `3c6215b5fac5cafb94e8d10659fb1750c039203db6de71bb6c505f535c791017`.
- `node/historical_tests.rs`: `c0ac61dd698653107876ece6b045dfbf84368667057db4ef8e7f131798ee316b`.

Focused result SHA-256:
`66d57f926652efb1d3359674abb153898ecd9c4eab46cfc20b617a1fb22f7aaa`.
Build result SHA-256:
`3caea6818022f5e454ef30f1c607717fd951f64dfea7cfdab14256c51fab112e`.
External receiving-pin receipt SHA-256:
`eceec4ec502c5684a8103880ef777623f755b4a21f7cfc2f3eca18f2d59caeaa`.
Scoped lint receipt SHA-256:
`5c97d41292bc4c5321fa54c89c3c91f2ba292c19c38847536f1b94f692513fa7`.
Read-only closeout receipt SHA-256:
`387dc710d9d99474745e59128c1f7343ebebd2b86a34ed41b5f461f02e1b735f`.
The lint summary matches the earlier slice's count-only result; the new named
lint unit ran against these source pins. It is not a substitute for source
identity or independent review.

## Remaining boundaries

This proves only a bounded four-carrier local receiver/cold-query mechanism,
not transport interruption or continuation over two hosts. Full3080 prefix
query cost under the unchanged allowance, subsequent resumed native ingestion,
network churn/preferred-branch convergence and sustainable operation beyond4096
remain UNPROVEN. The previous full3080/cold evidence belongs to its exact earlier
ELF, not this new source. See [that report](F04_NATIVE_HISTORY_RESTART_V1.md).
Independent acceptance, production privacy/practical speed, wallet recovery and
whole-core/security/release readiness are not established. No public rollout or
profile activation is implied.
