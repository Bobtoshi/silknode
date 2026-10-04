# F0.4 pinned public-range receive binding

`PublicHistoryV1::decode_range(bytes, start, count)` binds received transport
bytes to the exact requested window in an independently content-pinned public
history manifest. It returns the existing borrowed `RangeBatchV1` only after
every member matches. Bare `RangeBatchV1::decode` checks framing/resource bounds,
not source-row identity.

## Implemented boundary

The caller selects a manifest using an already admitted public genesis and an
independently retained content hash. Peer HEAD/checkpoint/hash claims are not
receiver validity. The receive check requires the requested count (clamped only
at that manifest's actual end), exact carrier length/hash at every requested
position, and static candidate ID/context/framing matching the closed row.

Partial/trailing/short/unsolicited ranges, reordered or duplicated members,
wrong-position replay, changed late members and foreign rows refuse as a whole
before any carrier list is returned. Byte-identical retries of the same request
remain acceptable, not permission to retry an unfinished native job or renew its
budget. Identical common-prefix bytes are not rejected merely for provenance;
this binds bytes, not peer reputation or the source's latest preferred branch.

Results remain UNVERIFIED carriers. Identity/static decoding do not verify work,
proofs, graph order, ledger state or a source checkpoint. Every carrier must use
ordinary `Node::ingest` and existing bounded reconciliation/Ready checks. Static
whole-batch refusal is not atomic native admission: a later native refusal does
not erase earlier valid admissions. No cursor, saved validity, source node store,
previous HEAD or wallet is imported.

Response bytes remain borrowed from the caller. There is no new body copy,
dependency, service, wire field, consensus/commitment byte, resource limit,
release default or authority-bearing constructor. Existing32-carrier/4096-history
bounds remain. Transports must bound reads before allocating response storage
and enforce their own aggregate resources. Opening a client manifest does not
require importing source carrier files; received bytes are checked against owned
rows. Existing file-backed `read_range` and bare framing behavior are unchanged.

The gated historical ingestion/prefix/repeat paths now use this binding before
ordinary ingress. They compile but their changed native paths were NOT rerun.
The earlier full3080/cold PASS applies to its exact source30 ELF, not this new
source31 ELF; see [the native report](F04_NATIVE_HISTORY_RESTART_V1.md).

## Focused research-VPS verification

Three new synthetic checks PASSED in0.06s: borrowed exact windows/tails/retries;
partial/trailing/short/reordered/duplicate/wrong-position/foreign-row refusal;
bad requests/empty inventory/pinned false ID refusal. Their fake proof bytes
were never admitted as work. Service113ms/CPU102ms/peak8.7M/swap0.

The changed static historical check PASSED3080 original carriers/97 ranges in
0.69s, using the selected genesis/manifest and bound decoder.
Service733ms/CPU145ms/peak10.4M/swap0. Native work evaluations0, payment proof
verification0, NodeStore opens0, mining/new proofs0. Passed full replay was not
duplicated. Peaks are systemd's reported values, not a whole-node RSS claim.

Locked/offline Rust1.93 release build PASSED: service41.544s/CPU41.281s/
peak416.6M/swap0. Compiler-only Tasks16 remained3GiB/one CPU/20min/1000CPU;
test units remained Tasks4/3GiB/one CPU/noSwap/60wall/30CPU, strict read-only
system/home, no network/capabilities/listeners, only the existing64MiB synthetic
tmpfs writable. Old historical owners/corpus were not modified or reopened.
Production changed-span Clippy PASSED with zero new findings;156 outside-span
baseline findings remain separate. Three-file rustfmt ran on the VPS.
No Mac build/test/proof computation or new dependency was used.

Tested ELF SHA-256:
`1f198736ae6e33fee867f0444b3b0b6ced0867e6ca3009a54ea61cb558681292`.
Changed-source SHA-256:

- `history.rs`: `5664874dea734608d4cefd0871753ed3b38e482e28a3ee1a31124ad68bdb9198`.
- `history/tests.rs`: `1e6eed2f6db2a3a1cae3cfaffabf55becc0803a1e3920d14776b792cd90b8768`.
- `node/historical_tests.rs`: `d11baab61cffd44b1b9f90f3675812aa389a20282b33458d04dd5faa40d5e019`.

Focused result SHA-256:
`172ca13c285698235421a9cff90acf8e97b6babb117a895ebdca21fbb29e0048`.
Build result SHA-256:
`7fc6a3a6d400c639802803694b4cca7b3cc738443f5fed3610721905b4ade8bf`.
Changed-span lint result SHA-256:
`5c97d41292bc4c5321fa54c89c3c91f2ba292c19c38847536f1b94f692513fa7`.
These are exact-source custody and bounded execution evidence, not mathematical
proof or independent whole-core acceptance.

## Remaining gate

The receiver can now derive a read-only resume hint from its own freshly checked
membership and original bytes. Four genuine carriers and a separately pinned
cold-process query passed; damaged original bytes refused after a warm query.
See [the receiver-prefix evidence](F04_RECEIVER_RESUME_PREFIX_V1.md). This does
not establish two-host transport or resumed native continuation.

The source/window binding primitive is implemented for independently written
transport modules. Later [operator integration](F04_HISTORY_OPERATOR_V1.md)
passed a bounded interrupted SSH static-source/eight-carrier receiving sequence
and fresh cold continuation/state parity. Native P2P/independently operating
peers, preferred-branch convergence and churn remain UNPROVEN. Sustainable operation
beyond4096, privacy/practical speed, wallet-key recovery and whole-core/security/
release readiness are also not established. No profile is activated or higher
horizon supported merely because this static slice passed.
