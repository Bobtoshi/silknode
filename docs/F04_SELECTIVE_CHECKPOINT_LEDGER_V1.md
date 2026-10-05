# F0.4 selective checkpoint ledger preparation

Private, valueless research. An admitted checkpoint with no envelopes now keeps
unchanged recovery, nullifier/effect and accepted-output payloads disk-retained.
It materializes only executed/reward histories, which it actually appends.
A batch containing any envelope still follows the complete-materialization
mutation path, including duplicates/conflicts. No peer flag selects this path.

This describes the frozen selective-preparation revision below. The later
[retained mutation and rollback milestone](F04_RETAINED_LEDGER_MUTATION_V1.md)
replaces that remaining materialization path; its evidence is recorded separately.

This required replacing borrowed resident invariant reads with checked streams:
the same economic count/conservation and reward-row rules are shared with the
existing public validator. Complete reward rows are checked against complete
executed history; every output-link page is qualified before its last position
is checked. Hashing freshly qualifies all unchanged private hash inputs. A
scratch state is returned only after complete hashes, invariant reads and the
final checkpoint budget check pass. Retaining a reference is not validity.

Consensus/commitment/checkpoint/page/delta bytes, money/work/proof rules, 4,096
history policy, cache charges, runtime budgets and release defaults are unchanged.
No new saved validity, received-state API or publication path is introduced.

## Changed-path evidence

Frozen test ELF:
`e1f03fee5be4d69682db7ca91dc17567c025b07055c2c8da700e5ab92895c932`.
Compiler-only build plus five focused checks PASS on the authorized research VPS:

- Synthetic selective/full preparation: exact retained private page identities,
  unchanged state hashes/manifests, no HEAD; complete invariant reads refuse a
  mismatched execution lineage, missing late output/reward/executed pages and
  expired budgets. Full mutation preparation still materializes all collections.
- Existing economic truncated/extra/reordered/altered-row refusal and paged
  accounting/prefix/balance oracles pass with the shared rules.
- Fresh genuine 24-carrier admission reaches three checkpoints. The third
  admitted batch is explicitly empty; scratch execution reproduces the exact
  actual checkpoint manifest while private page identities remain retained.
  Mutable executed/reward histories remain resident. No ACTIVE markers remain.
- A second fresh 16-carrier nonempty fixture reproduces five representations,
  two checkpoints, pool 58/burned 2/seven leaves, original scratch execution and
  source/page refusals. Its final deliberate damaged-directory reopen STOPs;
  the diagnostic owner/ACTIVE_REPLAY is preserved and never reopened/adopted.

Build: 50.793 service / 50.694 CPU seconds, peak 447 MB, swap zero.
Three synthetic checks: 305 service / 215 CPU ms, maximum peak 9 MB, swap zero.
Native24: 9.420 service / 8.660 CPU seconds, peak 324.2 MB, swap zero.
Native16: 12.599 service / 12.384 CPU seconds, peak 325.8 MB, swap zero.
Each native check: one CPU, 3 GiB/no swap/four tasks, 120 wall/100 CPU seconds;
existing vertex/checkpoint budgets remain unchanged. Both fresh owners are on
the existing capped 1 GiB task volume under
`/var/tmp/silknode-replay-pages-lab-v1/extensible-ancestry-native-fs-v1/work/`:
`selective-native24-v1` and `selective-native16-v1`. Original 4 GiB image
size/block/mtime/ctime pins remain unchanged; task UID processes are reaped and
all successful check phase intents are closed.

No mining, new proofs, wallet secrets, native fork/reorg, P2P, independent-peer,
wallet-recovery or separate-process cold-success result is part of this check.
Old 72/520/3,080 native results remain on their own frozen ELFs. Unused resident
compatibility helper warnings remain; this is not a lint-clean claim.

Receipts in `/var/tmp/silknode-replay-pages-evidence-v1/`:

| Receipt | SHA-256 |
| --- | --- |
| `selective-reducer-build-v1-result.json` | `32c95821c48b898f462251b98d8bd9ba3741bd10aa113aacbe256bec78416986` |
| `selective-reducer-check-v1-result.json` | `890d0598ecf36187a5ea52d87d460083577c6af060753dcaf0f82167f026204a` |

Compiled changed source under `prototype/crates/silk-f04-node/src/`:

| Source | SHA-256 |
| --- | --- |
| `state.rs` | `89b3b24115b984e733c186bebef45053384abcb66a359e466f66d5e4a1920d93` |
| `economics.rs` | `e6362ffafb98609574a7e39951d79faeb521f3c382ec630e93dd65bb27e81d89` |
| `node/historical_tests.rs` | `fe380049e00d0c46ef41fd69d7f378c888b2f5d5d16d145ebecf4ee89d01691d` |

## Remaining core integration

Executed/reward mutation still loads complete histories, nonempty payment
mutation still loads all private collections, and rollback restoration/public
compatibility views remain resident. Coherent retained-prefix/bounded-tail
mutation and its semantic/failure-atomicity checks are needed before claiming
bounded whole-reducer memory. Extensible physical trees are not integrated
beyond-4,096 native admission; graph/index/ledger/sync/generation policy and
larger native sync/restart/competing-branch/private journeys remain separate gates.
