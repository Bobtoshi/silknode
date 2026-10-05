# F0.4 local history capacity, version 1

Follow-up: [bounded history inspection](F04_STREAMING_HISTORY_INSPECTION_V1.md)
removes full order/executed buffers from inspection and interval selection. The
limits here remain unchanged; this is not beyond-horizon native acceptance.

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

## Storage refusal before an attempt

Foreground job creation now distinguishes a definite quota/free-space refusal
before reservation charging or any write from an uncertain start. Admission,
checkpoint and mining-entry preflight leave the node healthy on that definite
local pause. Restoring capacity does not require reopening a healthy writer or
renewing an unfinished job allowance: no attempt was started.

An existing unfinished attempt, a poisoned store, uncertain reads, and every
write-stage or post-marker failure retain the original STOP behavior. Charges,
job/replay pointer encoding, quotas, host margin, consensus and resource caps
are unchanged. This is not a disk reservation or native-runtime qualification.

Only the new storage checks can be selected with `--test range_component
storage_preflight_ -- --test-threads=1` in the command above. They use a controlled
fixture margin mapping, a permission-denied write, and a synthetic retained
attempt. The first unverified public carrier is used for preflight framing only;
no native work, proof verification/generation or valuable operation is performed.

All three focused macOS storage checks passed, as did strict linting of the
external component target and formatting/diff checks. An initial fixture decoder
refused the line-wrapped hex before any admission; whitespace normalization
corrected that test-only failure. No previous capacity or native-work checks
were repeated for this storage increment.
