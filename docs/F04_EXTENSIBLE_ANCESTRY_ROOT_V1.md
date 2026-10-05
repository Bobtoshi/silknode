# Extensible receiver ancestry roots

Follow-up: [extensible physical order geometry](F04_EXTENSIBLE_ORDER_GEOMETRY_V1.md)
removes the next hard-coded tree shape, with separate synthetic evidence only.

Implemented private, valueless core mechanism, 5 October 2026. The fixed
eight-leaf address array is replaced by an immutable, sparse eight-way page
tree. Updating one leaf copies its branch path; a retained ancestry owns one
root reference, not a complete leaf-address vector. The node-wide graph/order/
ledger/sync policy remains **4,096**. This is necessary representation work,
not permission to lift a counter or a claim of whole-core completion.

The existing 112-byte `SNF04AP1` leaf bytes are unchanged. New receiver-local
320-byte `SNF04AD2` branches bind domain, level, base coordinate and eight
optional child addresses. Live `SNF04DP2` directory slots use a 34-byte ancestry
root entry, reducing the slot from 561 to 331 bytes. These are auxiliary local
formats only: canonical carrier/work/proof/order/generation/checkpoint/state
bytes, validity rules, release defaults and resource allowances are unchanged.
Original objects are retained; no migration, pruning or deletion is performed.

Cold reopening still revalidates original complete records and derives the live
directory after ordinary admission. A root is not importable validity. Reads
check anchored regular single-link files, complete hashes, domain, coordinates,
types and framing. One operation's positive leaf reuse additionally binds its
owned immutable root and live context; no negative/error/persistent validity
cache is introduced. Complete strict-past scans qualify every branch/leaf even
outside a requested prefix before returning positions. Failed staged updates
cannot install half a closure; uncertain writes retain the existing STOP policy.

## Changed-path evidence and exact versions

Sixteen affected ancestry/directory/writer checks passed on test ELF
`a32aa006bfa8f23f2c11093a902a199674bcd3d78e1d78f82c02e3f9151d6d06`.
A new synthetic depth-four case reached position 1,048,575, compared exact
positions/forks/unions and refused deep missing, wrong-context/coordinate,
hard-linked and expired inputs. These are auxiliary synthetic positions only.

Review then found that growing an empty root by several levels retained an
empty lower branch. The correction increases empty depth without materializing
that branch. Exact sparse-first cases 4,095 / 4,096 / 32,768 / 65,536 / 1,048,575,
subsequent insertion of zero, prior-root immutability, and affected current flat/
horizon oracles passed on corrected ELF
`167983eaf366bda9045ae9c5530bbae29dcbeada3e06eb1b1ebc5db69b39f0cc`.
The final correction build took 52.267 service / 51.953 CPU seconds, peak 447.5M,
swap zero; the three focused cases used 105ms CPU in total. No lint-clean claim.

One genuinely unmet native boundary separately passed on the **preceding**
source-36 ELF `626cb658a40aa8ad2a25e02893478c12635c4622991f73ab1b60d74445950931`:
520 original genuine carriers through ordinary admission, 65 checkpoints, and a
separate pinned cold OS process. This crosses the new ancestry branch at 512
positions. It does not exercise the later sparse-only high-depth correction or
extend that native result to its new ELF. The unchanged native case was not rerun.

Fresh and cold exact parity:

| Field | Value |
| --- | --- |
| Local HEAD | `abee9ee95e50f4a3aa31a4690dc4ae0e1cfb38b6ff9969054a0a2920c39f1811` |
| Canonical order hash | `d4f9bc8373f474c8f57c2a603c5f5ceff9d33860cf0b8923c18ce31f3075d9e7` |
| Public ledger hash | `9fd1ce3ebf4442a38ba727a833e1ae1b9ddf7fcfd56eb25cc3652feb9ae05b42` |
| Checkpoint 65 | `61127b4438a14bfcdd2fe3d130f34c3236c214c57c948991089fc2b033b59e1b` |
| State digest | `7698b9a9f7dfdcc34bf5706c56da717374c1a2c2aeb72de541dbce1cec7a9c93` |

The two native units used 362.230 CPU / 385.657 service-wall seconds in total,
peak 631.4M, swap zero. Original per-vertex 2 CPU / 5 wall seconds and checkpoint
10-second allowances stayed unchanged. Outer native units retained one CPU,
3 GiB, no swap, four tasks, each at most 350 CPU / 500 wall seconds, under one
1,100-second pair window. Compiler-only builds used the existing 16-task exception.
These measurements include verification/replay and are not a speed benchmark.

The new exclusive 1 GiB / 131,072-inode capped fixture, successful receiver,
frozen binaries and receipts are preserved. Both phase intents closed, task UID
processes reaped, ACTIVE_JOB/ACTIVE_REPLAY absent, previous-head recovery false.
The original 4 GiB image's size/blocks/nanosecond timestamps were unchanged.
Older failed owners were not reopened. No mining, new proofs, wallet secrets,
peer listener, seed/node deployment or real-asset operation occurred.

Original receipts under `/var/tmp/silknode-replay-pages-evidence-v1/`:

- `extensible-ancestry-check-v1-result.json`: `b6f9cd95d04668394e5d7e4d5bed7e4da1b0f002fa22db557bd5db8dc42fbfd3`.
- `extensible-ancestry-native-v1-result.json`: `e8e28e2e1a146153e60944476912c5c69a778efe07adc863d90437b3a06bde29`.
- `extensible-ancestry-build-v4-result.json`: `7674ba1cacc506dfec44104d21536e8d54185272e6995cd894724f28dcd77a34`.
- `extensible-sparse-fix-v1-result.json`: `bf3f407d35ac76bddd02fdcec0a768f2449540fbc1e9b9d00b873d166ed69053`.

Build receipts pin exact source bytes for their respective binaries. Historical
[source-30 full 3,080](F04_NATIVE_HISTORY_RESTART_V1.md),
[source-33 SSH-eight](F04_HISTORY_OPERATOR_V1.md), and
[source-35 native-72](F04_NATIVE_HISTORY_BOUNDARY_V1.md) results remain separate.
Beyond-4,096 integrated admission, native P2P/independent consensus peers, ongoing
churn, private wallet recovery, privacy/performance and release readiness remain
UNPROVEN. The next linked representation is physical order-tree geometry, followed
by coherent graph/index/ledger/sync/generation policy and resource integration.
