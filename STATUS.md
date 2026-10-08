# Research status

As of 8 October 2026. This is a source alpha, not production software, an
independent security audit or whole-blockchain completion.

## Public implementation

The existing public F0.4 core includes shielded payment/wallet components,
full-data DAG admission and bounded durable history/recovery. The optional
zero-value testnet adapter remains separate. The new default-off IM3 source
slice adds original client integration, full three-relay gates, signed producer
release, original-link cancellation, durable round sequencing and mandatory
runner ports. R2 input collection/dispatch prerequisites are included.

The small [local smoke example](GETTING_STARTED.md) is the public entry point.
IM3 interfaces and ignored fixture harnesses are inspectable source, not a
turnkey anonymous network. Private readiness and fault controllers are excluded.
No fresh build, test, native run or proof was performed for this export.

## Separate completed private demonstrations

These are distinct private, valueless, one-operator experiments. They must not
be combined into a claim that one run established all properties.

| Demonstration | What it established within its fixture | Boundary |
| --- | --- | --- |
| Joined ordinary client and recovery | An actual wallet client, original A→C→B gates and three producer offers fed fresh-node settlement; separate cold sender-only and recipient-only processes recovered that same payment/seal | Thirty-one cover statements were reused. Recipient value remained pending maturity. No independent custody or anonymity claim |
| Two fresh timed clients | Two distinct clients each generated fresh B and C proofs under original deadlines; full 32-member gates produced three identical ordinary offers | Thirty other members' proofs were prepared beforehand. Fixed real/cover slots and public toy credentials; no settlement/recovery in this run. Recorded in `bcb3532` |
| Hidden-assignment source-link trial | One prediction was frozen before evaluator reveal; the predeclared A-outgoing/B-receipt timing-rank prediction was wrong | Rejects that hypothesis in that trial only, not weaker advantage or other attacks. Recorded in `556d52bf` |

The attack saw the allowed A+B/producer projection, not C's internal view or
honest secrets. Four synthetic invalid observation controls detected concrete
identifier bridges; they were not valid live attack transactions. The operator
retained root authority. Process isolation and independent receipt review do
not establish independent custody, general attack sensitivity or a security
audit. That trial performed no same-run settlement.

## Still incomplete or unproven

Private fault-path evaluation is unfinished: latest attempts failed during
preparation/startup before the intended honest fault path. Those failures are
not successful privacy trials. Earlier toy cancellation/restart regressions
do not satisfy the hidden-assignment fault/restart evaluation.

System-wide anonymity, negligible adversarial advantage, Monero-equivalent
privacy, accepted membership setup, independent relay custody, qualified
clocks/delivery, 32 fresh timed honest clients, sustained resource margin and
production readiness remain unproven. No public service activation or change
to consensus/payment bytes follows from this source publication.

See [IM3 source/provenance details](docs/IM3_EXPERIMENTAL_V1.md) and
[Security](SECURITY.md).
