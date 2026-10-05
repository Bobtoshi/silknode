# F0.4 bounded history inspection

Follow-up: [bounded order publication](F04_STREAMING_ORDER_PUBLICATION_V1.md)
removes physical page-payload staging from the writer without changing formats
or limits. Its separate source/ELF evidence does not extend these test results.

Private, valueless implementation slice, 5 October 2026. Reconciliation,
publication-capacity preflight and selected-parent qualification no longer
reconstruct a complete preferred-order ID vector or materialize the complete
executed ledger merely to inspect prefixes and select eight carriers. This is
a scaling dependency, **not a history-capacity lift**.

## Mechanism

The typed reader scans the existing shared order tree, hashing the unchanged
canonical `SNF04OR1` header and every ID. Held-directory, inode, type, owner,
shape and page-hash checks remain. The complete canonical hash must match its
filename before a result returns. Private visitor observations are provisional
on any later error; they cannot publish state or confer validity.

Shared traversal holds two branch pages and one 64-ID leaf. Legacy raw orders
retain their bounded whole-object reads; compatibility callers requesting all
canonical bytes still receive a complete buffer. No objects are migrated,
rewritten, pruned or removed, and no durable format changes.

An operation-local executed-ledger comparison checks one 64-row page at a time:
actual hash, context, ordinal, framing, count and closed row decoding. It releases
the old decoded page before loading the replacement. Every page is qualified
even after an early mismatch or an empty/short preferred order. Missing later
data is an error, not an apparently valid shorter prefix.

Inspection returns prefix lengths and at most eight selected IDs; there are at
most six comparison slots. No global payload/validity cache or public import
constructor exists. A new call reads afresh under its original cumulative budget.
Normal reconciliation compares only the current ledger. Divergence requires a
second complete order scan against the eligible existing rollback states (at
most five), under that same budget. Ordinary full ledger qualification still
precedes rollback publication and checkpoint execution. The reducer appends
the exact eight verified IDs; Ready/reconciliation/archive prefix rules remain.

## Exact-source component evidence

Final locked/offline Rust 1.93.0 release lib-test build passed on the research
VPS: service 44.881s, CPU 44.843s, peak 406M, swap zero. Two new synthetic checks
passed in 0.06s (service 110ms, CPU 81ms, peak 9.7M, swap zero):

- Raw/shared boundaries 0, 64, 65, 513 and 4,096; exact canonical bytes; bounded
  visitor pages; missing later leaf, canonical-header hash mismatch, undersized
  read and expired original budget refuse.
- Three-page executed ledgers; exact multiple-state prefixes and interval
  128..136; state-count and offset bounds; neither divergence at zero nor an
  empty preferred order conceals a missing ledger tail.

Final changed production-span Clippy reported zero diagnostics; 157 outside
baseline diagnostics are separately retained. Service 26.190s, CPU 26.094s,
peak 222.1M, swap zero. This is not a whole-source lint-clean claim.

These checks are serializer/inspection models, not genuine work, payment proofs
or native checkpoint acceptance. No passed SSH-eight-carrier or historical
3,080-carrier/cold run was repeated or transferred to the changed ELF.

Final test ELF SHA-256:
`5931e9db84e166b79ce2ca7101c862224f8ad4bd76dc72e2b13b0179f7677ba9`.
Build receipt SHA-256:
`1f96551d6133fe8a3865f268a81b8cbd7381617b1ed8ab1b490cfd33ed32e03a`.
Focused check receipt SHA-256:
`21f94fe62fec1d1b9167a130ff7dea090c1f039a156ce3287f33cdc6a1510c99`.
Changed production-span lint receipt SHA-256:
`ccda51225baa91eedafcb055791bdb75027483373ee970a9ab66aa663ef080f0`.
Receipts remain under `/var/tmp/silknode-replay-pages-evidence-v1/` as
`streaming-inspection-build-v2-result.json`,
`streaming-inspection-check-v3-result.json` and
`streaming-production-check-v2-result.json`.

The first synthetic runner omitted the outside-volume host-margin path and
refused before Store creation. Its failed receipt remains; only the runner
changed for the corrected first-source pass. Final-source changes release the
old decoded page before replacement and correct three scoped lint findings;
they received a separate build and affected checks. A later lint collector
initially selected an absent evidence directory and stopped before compilation;
its script is preserved, and the corrected collector ran once. Earlier outputs
and frozen ELFs remain; none is relabelled as a final pass.

| Final node source | SHA-256 |
| --- | --- |
| `src/core.rs` | `914de21a49d44984c6b20b7a295c8876af38e042f91bf6efc2c9f48b4d241a45` |
| `src/core/order.rs` | `f0c467011b4958bb111d60732324332d8c94523b28091c18805c2a82da19fd6b` |
| `src/state.rs` | `0c81c55ed87a31f778c8b694386f175a3964b27451f1a87325fc4cd6f0281c59` |
| `src/state/history.rs` | `587817386a501841f24ae0e609618e002c65b6667d3fc0432869931f1fe00723` |
| `src/store/order.rs` | `8e6f9605fa3a2e29e5ad4b43602b1f6ec919b4a19debbca5e4dbecec6b8c2670` |
| `src/store/order/tests.rs` | `7b36ff2f8fb4c9e847241e53cccf76fd46ebc69d4a8a94a3934b41ae25c20f2f` |

## Coupled limits still open

The 4,096 graph/ancestry/index/order/ledger/sync horizons and 20,000-generation
replay/publication horizon remain. Ancestry has eight fixed 512-position leaves
and fixed inline directory slots; order storage has two eight-way branch levels.
Graph indexes, rewards/executed histories, canonical order validation and public
range/manifest framing enforce the same horizon. Cold generation traversal
derives its directory from the full original backward lineage. None can be
raised in isolation.

Graph derivation still produces full reference snapshots. Checkpoint execution,
hashing and economic validation still materialize affected ledger data. Original
archives and unreachable objects remain retained and quota-charged. This slice
does not make those costs constant or prove indefinite operation, whole-process
memory bounds, practical performance, native P2P, independent consensus peers,
payment privacy or whole-core/release readiness. Sustainable growth still needs
coordinated paged representations and fresh verifier integration, with explicit
resource refusal rather than pruning or trusted snapshots.
