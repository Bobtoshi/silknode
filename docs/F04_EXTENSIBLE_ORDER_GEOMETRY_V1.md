# Extensible physical order geometry

Implemented private core mechanism, 5 October 2026. Following
[extensible ancestry roots](F04_EXTENSIBLE_ANCESTRY_ROOT_V1.md), physical order
derivation and reading now calculate the necessary eight-way tree depth rather
than hard-coding two branch levels. The existing minimum depth stays two, so
every current page, descriptor and canonical `SNF04OR1` byte/hash is unchanged.
Publication still reserves the exact complete missing-page plan before writes,
regenerates pages one at a time, and publishes HEAD only after the original
sync/no-replace descriptor tail. One original budget spans the whole operation.

The production graph/order/ledger/sync policy remains **4,096**. Larger synthetic
physical shapes do not admit a graph or grant work/order/state validity. Page
coordinates retain the existing `u16` codec ceiling: at most 65,536 leaves,
not unlimited storage. This is representation work, not a cap-only lift or a
claim that the integrated history can already grow past 4,096.

One new focused synthetic case passed at 4,097 / 32,768 / 32,769 rows (three /
three / four branch levels). An independent bottom-up construction matched
every page byte and root against the production depth-first derivation. Real
private page writes/typed traversal reproduced all rows and their canonical
hash. Wrong level/base, missing final leaf, expired budget and overflowing
geometry refused; the production ordered-commit entry point still rejected
every over-policy input without selecting a HEAD. A directly affected existing
oracle also passed exact old page/descriptor bytes and publication charges.

Test ELF: `3eb9db66c5a3d856865a2f95aa927f288edba6d0292715899238dc6b40a523e6`.
Build: 53.213 service / 53.136 CPU seconds, peak 424.9M, swap zero, compiler-only
16-task exception. Two checks: 242ms service / 183ms CPU, peak 9.4M, swap zero,
native/test four-task limit. All computation was on the isolated research VPS;
no work/proofs, networking, old-owner reopening or unchanged native runs occurred.

Receipts under `/var/tmp/silknode-replay-pages-evidence-v1/` pin their exact source:

- `extensible-order-build-v1-result.json`: `3457f31eadfbc6ff987203f6f9cd73caedae6f9e1bb8f6fd027e9cb28b75b4e8`.
- `extensible-order-check-v1-result.json`: `0d6e9830b49108727b16582d05bf6824f389cda6fc67fe3efd26e08ac3d11bd4`.

The source-36 native 520/cold result belongs to its preceding frozen ELF, not
this new binary. No new native, beyond-4,096, P2P, privacy, speed or whole-core
acceptance is claimed. Full ledger materialization, graph inventories and
coherent graph/index/ledger/sync/generation resource policy remain integration work.
