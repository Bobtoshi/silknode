# F0.4 valueless economic ledger checks v1

The checkpoint reducer now independently checks every existing public reward
record against its contiguous execution position, exact executed vertex ID and
fixed amount. Previously its invariant checked reward count and total issuance,
but not those individual record fields. This is a stronger local invariant, not
evidence that a peer could previously mint money or bypass ordinary replay.

The same verifier checks context, complete eight-position checkpoint boundaries,
the unchanged 4,096-position / 50,000-effect reference limits, accepted effects
against the 32-envelope-per-position ceiling, private burn count and checked
private-pool conservation. The reducer stages checked pool subtraction and burn
addition before any accepted-effect writes. An inconsistent locally constructed
ledger is a local unavailable error, not evidence of peer invalidity.

Existing genesis-committed parameters remain unchanged: 10 NONTRANSFERABLE
public credits per executed position, maturity after 16 further positions, and
one private unit burned per distinct accepted effect. Parameter serialization
and execution now share the same fixed constants. There is no configurable
monetary policy, new profile activation, spendable reward, fee redistribution,
emission decay, supply cap or sponsorship mechanism in this increment. Public
credits cannot replenish the separate private pool. Private initial supply still
depends on the admitted allocation premise; this does not publicly prove hidden
initial supply. The public-zero profile still has no private allocation.

## Independent consumer interface

`BranchState::economic_ledger()` borrows the receiver-derived execution IDs and
112-byte reward records without copying history. `EconomicLedgerV1::validate`
checks those records against an independently supplied full genesis context
domain and initial private allocation. It allocates no additional ledger and
scans at most the unchanged reference horizon. Checkpoint validation uses this
same function, including canonical execution and parent-prefix reconstruction;
there is a job-budget check after the completed state invariants.

A caller can construct or alter an `EconomicLedgerV1` for negative tests.
Successful validation is an accounting consistency result ONLY, not a work,
Sapling proof, SG-0 order, owner/nonce binding or checkpoint acceptance token.
Those still require ordinary receiver admission and replay. A self-declared
matching context is not authentication. A claimed initial allocation is not
proof of supply. No wire, hash, state manifest, delta or checkpoint encoding has
changed, and no borrowed view is persisted as trusted authority.

## Focused reproduction and limits

From the source checkout, with the existing pinned Rust toolchain/cache:

```sh
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=prototype/target cargo +1.93.0 test \
  --offline --locked --manifest-path prototype/checks/peer-sync-v1/Cargo.toml \
  --test range_component economic_ledger -- --test-threads=1
```

The four checks cover the byte-pinned public-zero genesis and committed rule
values; mutations of every row's amount/position/vertex and reordered/missing
rows; foreign context, private conservation, counter mismatch and overflow;
and synthetic rollback/re-execution prefixes with recomputed, not accumulated,
issuance. They call the compiled public library. Nonempty reward rows are
explicitly synthetic, not newly admitted or mined carriers, and the prefix
check is not a live fork journey. No native work, new payment proofs, network
operation or previously completed journey was rerun. Production monetary
numbers and independently operated network acceptance remain separate work.
