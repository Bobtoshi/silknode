# F0.4 streamed graph publication

Private, valueless research. Durable graph insertion no longer constructs a full
resident ID/ordinal map. A complete checked sorted visitor merges one newly
receiver-derived ID into the original canonical 64-row packed index pages.
The ordinal must equal the current length; duplicates, foreign contexts,
bad permutations, missing pages and expired budgets refuse the result.

Durable publication no longer materializes complete old/new graph directories
or a full staged index map. It qualifies the staged index into the existing
bounded ID/ordinal vectors, completely checks the original index against those
IDs, and compares original/staged directory rows with private operation-scoped
page readers. Each directory reader owns at most 64 decoded descriptors. Shape,
full prefix identities and the appended slot must pass before either current
index or directory is assigned. Failed/partial reads grant no graph credit.
No operation snapshot survives publication or reopen as validation authority.

Exact SNF04IP1 and DP2 bytes, sorted page packing, source/consensus/commitment/
hash/delta/recovery bytes, verifier/economic rules, modular public APIs,
reference limits, original cumulative job budgets and release defaults remain
unchanged. Newly retained auxiliary pages are provisional under the existing
fence; failure need not undo those immutable files, but returns no completed
directory/state/HEAD. Explicit public resident compatibility paths remain.

This removes a full-map/two-full-directory payload-copy bottleneck on actual
admission and cold replay; it does not remove full-data validation or make
whole-node memory constant. Directories, live capabilities, ID/ordinal vectors,
permutation bits and other metadata still grow within the unchanged bounds.
The 4,096 policy is not raised. Coherent graph/index/order/ledger/sync/generation
resource support and larger native integration remain separate required work.

## Changed-path evidence

Frozen ELF:
`772f83cdbd5b155a20bbeba2b0078e25a6afd984c4517a513893500a4cbed7c2`.
Compiler-only build and five exact focused checks PASS on the research VPS:

- NEW streamed insertion oracle at 0/1/63/64/65/129/4,095 old rows, with
  low/middle/high added IDs: exact old literal packed page IDs, complete map
  parity, immutable prior state; duplicate/wrong ordinal/context, absent old
  tail, bad permutation, expiry and unchanged horizon refuse without HEAD.
- NEW 65-to-66 synthetic durable graph publication across the directory-page
  boundary: staged index pages match the literal oracle; missing current tail,
  staged directory tail or staged index tail refuse without partial graph
  credit. Restoring exact bytes permits publication. These are synthetic rows,
  not accepted native work/proofs.
- Essential affected existing current/staged index-page refusal and private
  directory reader ownership/read-failure checks pass.
- Essential affected genuine saved-carrier admission/payment/competing-branch
  rollback and two-parent merge pass on THIS ELF, including exact checkpoint
  parity, retained payment prefixes, zero-staged rollback, opposite ingress,
  same-process cold reopen and exact-repeat no-new-credit. Two receiver stores
  share one host. Existing authenticated public carriers only: zero new mining,
  generated proofs, wallet secrets or valuable assets. Inherited structural
  `new_vertices=2` logging is not newly mined work.

Build: 51.578 service / 51.505 CPU seconds, peak 459.7 MB, swap zero.
Four synthetic checks: 322 service / 235 CPU ms, maximum peak 3 MB, swap zero.
Genuine changed-path journey: 25.856 service / 25.263 CPU seconds, peak 583.8 MB,
swap zero. Checks use one CPU, 3 GiB/no swap/four tasks, 120 wall/100 CPU seconds;
compiler-only tasks use the existing 16-task exception. Original vertex and
checkpoint budgets remain unchanged.

New native owner under the existing capped 1 GiB task volume:
`/var/tmp/silknode-replay-pages-lab-v1/extensible-ancestry-native-fs-v1/work/graph-publication-native-fork-v1`.
Successful phase intents close, test UID processes are reaped, both new stores
have no active markers, and original 4 GiB image size/block/mtime/ctime pins are
unchanged. Older failed/diagnostic owners remain unopened.

No unchanged 16/24/520/3,080 gate is repeated. Older native acceptance does not
transfer to this ELF. No beyond-4,096 admission, P2P, independent-host consensus,
wallet recovery, separate-process cold-success, privacy/speed or release
acceptance is claimed. Existing unused resident history-helper warnings remain.

Receipts in `/var/tmp/silknode-replay-pages-evidence-v1/`:

| Receipt | SHA-256 |
| --- | --- |
| `graph-publication-build-v1-result.json` | `77aa48df4ac2b0c3c0f34e32a67e11d62b51b684de8ed68c820df2b3e641fb8a` |
| `graph-publication-check-v1-result.json` | `3bf574695a61bbd4b99aeba45d24b505af90b3c1b415c5fe9b925cf630059ae7` |

Compiled changed source under `prototype/crates/silk-f04-node/src/`:

| Source | SHA-256 |
| --- | --- |
| `graph.rs` | `fac6a60d1ded2e35f41798fdc8f868421de9bdcb959802c77be77b85f0a873bd` |
| `graph/index.rs` | `8fdff4236567e7848bbe78da22930c1caa09b4f298b830800de1318e9fb62494` |
| `graph/directory.rs` | `0c36f6615439e9915f0ca362fde9e57264bf11d52f28d93f224ff02bb6c00147` |
