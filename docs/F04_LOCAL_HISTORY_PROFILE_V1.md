# Explicit receiver-local history resource profile v1

This is an implementation of a bounded LOCAL resource choice, not a consensus
upgrade, peer validity flag, production activation or larger-chain acceptance.
All existing constructors and release defaults still select 4,096 positions.
The explicit research API permits a nonzero multiple of eight up to 8,192.

## One immutable local choice

`capacity::HistoryLimitsV1` has a private field, a reference constant and a
checked constructor. It is not decoded from network traffic or serialized in a
head, vertex, state, delta, manifest or checkpoint. Operators must choose it
independently; an advertised source count is never permission to enlarge it.

The same choice is bound to Node/Core, Graph, Store/ObjectReader, live ancestry
context, retained index/directory/order, prefix cache and BranchState. A cache
cannot remember a state from another profile or derive against a different
graph profile. Graph attachment, ledger retention, ledger delta comparison,
index insertion, directory append and ancestry storage refuse mismatched local
bindings. Public resident compatibility paths retain their original horizon.

The graph, executed positions, reward rows, original order-object lengths and
public inventory bounds all use that one selected vertex envelope. The 20,000
generation ceiling, 313 x 64 replay-address geometry, object/storage accounting,
16 MiB crypto and 128 MiB prefix caches, 50,000 effects, 100,000 nullifiers,
100,000 recovery-effect allowance, admission/checkpoint CPU and wall budgets,
worker quantum limits and thread/process limits are unchanged.

Construction checks the complete linear-history generation envelope:
`1 + vertices + vertices / 8`; at 8,192 this is 9,217, below 20,000.
This is arithmetic, NOT proof that arbitrary forks fit. Admission still
preflights one admission plus a possible rollback and all necessary checkpoint
publications. Reconciliation derives its exact bound from receiver-owned order
and execution cursors; exhaustion refuses before accepting another job.

## Explicit modular entry points

- `Node::create_with_limits`: create using an independently chosen local profile.
- `Node::open_retained_pinned_with_limits`: fresh full replay of an operator-owned
  store using an independently retained HEAD pin and explicit profile.
- `Node::history_limits` and `history_capacity`: read local configuration and
  actual receiver-owned capacity arithmetic.
- `PublicHistoryV1::open_with_limits`: bind an UNVERIFIED inventory to an
  independently pinned manifest/genesis and chosen local inventory bound.
- `RangeBatchV1::decode_with_limits`: complete framing only, not admission.
- `EconomicLedgerV1::validate_with_limits`: full accounting/row checks only,
  never authentication of work, proofs, genesis or reward ownership.

Existing methods delegate to REFERENCE. No CLI default, public port, seed,
service or activation changes. Every carrier still enters ordinary admission:
fresh receiver-local time, work, crypto, SG-0 ordering and execution checks.

An intact retained header whose counts exceed local resources can only cause
refusal. It cannot establish validity. This refusal precedes ACTIVE_REPLAY,
preventing an accidental too-small local choice from burning a replay attempt.
Damaged/unsupported retained histories still obey the existing STOP rules.
Unpinned/verified-previous recovery entry points remain reference-profile only.

## Formats and verification boundaries

SNF04IP1 packed index pages, SNF04DP2 directories, SNF04AP1 ancestry leaves,
SNF04OR1 orders and original state/delta/checkpoint/generation bytes are unchanged.
A larger count is represented using the same physical pages, widths and hashes.
No saved profile bit, validity shortcut, imported graph, cached absence or
trusted remote execution result is introduced.

The Source43 VPS compiler/check receipts are versioned separately:

- Build v2 and check v1: seven NEW synthetic capacity/range/ancestry/index/
  directory/order-ledger-delta/public-history checks passed. They cross 4,096
  through 4,104, and ancestry/index/ledger/order exercise the selected 8,192
  boundary as applicable. Missing late pages and cross-profile bindings refuse.
  These rows/carriers are deliberately synthetic: NO native work or proof credit.
- The same frozen v2 executable passed a genuine SMALL saved-carrier journey:
  explicit 8,192-profile create, full replay of historical 16/15-position
  fixtures, private payment mutation, real sibling/merge checkpoint
  reorganisation, opposite ingress, same-process cold reopen and exact-repeat
  no-credit behavior. No mining or proof generation.
- Build v3/check v2 are the final additional local-profile preflight and public
  accounting-path checks. Their exact receipts, not this source description,
  determine completion. Unchanged synthetic gates are not attributed to the
  final v3 executable; they remain bound to the frozen v2 executable.

Only read-only existing public objects enter the genuine small test; its two
receivers are on one isolated research host. The old original/failed owners,
live services, wallet material and valuable assets are untouched.

## Still unproven

NO native chain above 4,096 has been accepted by this work. The independently
pinned large public input currently contains 3,080 unique carriers. Native
boundary acceptance needs compatible authenticated additional work, separately
approved generation/replay resources, full admission/execution and separate
process cold replay. Do not combine carriers from different genesis domains,
duplicate work, synthetic rows, or claim that selecting 8,192 proves capacity.

Two-host interrupted native sync/concurrent branch recovery, ordinary cold wallet
recovery and whole-system/network anonymity are separate unmet system gates.
Sapling proof checks are not a whole-system anonymity proof.

This implementation stays private/valueless until its exact source/receipts are
reviewed and signed and any separately authorised publication is verified.
