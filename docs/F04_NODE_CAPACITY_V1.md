# F0.4 local history capacity, version 1

`Node::history_capacity()` exposes read-only local resource metadata for node
operators and ordinary third-party modules. `HistoryCapacityV1::for_counts`
reproduces the arithmetic from unverified counts; it grants no graph, work,
ledger, disk reservation or peer authority.
`HistoryCapacityV1::reconciliation_generations` similarly exposes the remaining
publication bound from an exact shared-prefix count, not equal graph sizes.

The existing reference limits remain 4,096 admitted vertices and 20,000 retained
complete generations. Before a new admission or mining attempt creates an
incomplete job marker, the node checks room for one admission, a possible
whole-state rollback, and all complete eight-vertex intervals in the resulting
graph. Red vertices and cached checkpoints can reduce the actual publications,
but do not weaken this conservative bound. Exact already-known carriers keep
their existing no-new-admission path.

Reconciliation checks its remaining publication bound before starting a new
checkpoint job. Clock-only publication must leave those reconciliation slots
available. The ordinary final commit horizon check remains in place. A known
reference-horizon refusal is a local pause, not peer invalidity and not a failed
native attempt. Live I/O/resource races still retain the existing failed-write
and unfinished-job fences; this policy does not make a disk reservation.

These are local lifecycle guards, not changed consensus, commitments, work rules,
genesis, generation encoding, higher history limits or release defaults. They
do not implement pruning, history scaling or indefinite operation.

Focused public-API checks run from the repository root:

```sh
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=prototype/target cargo +1.93.0 test \
  --offline --locked --manifest-path prototype/checks/peer-sync-v1/Cargo.toml \
  --test range_component capacity_preflight_ -- --test-threads=1
```

The boundary checks use unverified count arithmetic. The ordinary-node check
creates an actual public-zero genesis store and checks read-only reporting and
clock-only publication. It does not generate work/proofs, fill a store with
20,000 generations, qualify native resource limits or prove sustained operation.

Four focused component checks passed: the two admission/count boundary checks,
the remaining-reconciliation/fork/clock-headroom check, and the ordinary-node
read-only/clock-publication check. Only the affected reconciliation and ordinary
node checks were rerun after exposing the shared arithmetic helper. The focused
external test target also passed strict Clippy; this is not whole-node lint
acceptance. No proof, maturity, mining or sustained-operation fixture was run.
