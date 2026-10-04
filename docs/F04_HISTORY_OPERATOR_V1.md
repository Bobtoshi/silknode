# F0.4 bounded public-history operator integration

The existing private, valueless, file-based `silk-f04-local` operator now connects
the public receive-window and receiver-prefix primitives to ordinary node
admission. No listener, daemon, peer discovery, wire format, dependency, consensus
byte, history horizon, wallet API or release default is added. Existing commands
remain unchanged.

`history-resume --history-root PATH --expected-history-manifest HEX32` requires
the same operator-retained receiving HEAD, genesis/domain and public parameters
as other retained commands. It performs ordinary pinned retained reopening and
prints `next_request_start` from `PublicHistoryV1::admitted_prefix`; no peer cursor
is accepted and the command does not flush the clock. The query itself is
read-only, but mandatory cold reopening still uses existing replay intents and
fresh native validation; this is not a filesystem-read-only reopen shortcut.

`history-ingest` additionally requires `--range PATH --start N --count 1..32
--max-steps 1..512`. It bounds the regular, non-symlink input to the existing
maximum range size, and statically binds the complete response to the pinned
window before parameter loading or opening a receiver store. After pinned
reopening, start must equal the freshly receiver-derived prefix. Each carrier
then uses ordinary `Node::ingest` and bounded reconciliation, stopping if Ready
is not reached. A later native refusal can retain earlier valid admissions;
this is not atomic batch acceptance. Failures remain nonzero, do not flush the
clock, and never imply native-owner retry or unknown-HEAD adoption. Successful
ingestion retains the existing clock flush and new external HEAD report.

The inventory remains only a content-pinned source selection, not source work,
checkpoint or preferred-branch authority. `next_request_start == source_total`
does not imply ledger convergence or absence of additional receiver records.
Transports must enforce their own aggregate OS limits and must not reopen failed
native owners. Existing per-vertex/checkpoint budgets and 4096 horizon remain.

## Focused VPS checks

The new syntax/bounds case passed in the initial test binary. It covers required
manifest/local pins, canonical start/count/step bounds, inapplicable resume start
and unsupported peer-cursor flags. The unchanged passing case was not repeated.
The partial-response pre-open fixture initially selected an unsupported genesis
profile, then an invalid empty private allocation; both failures were test
fixture construction/configuration, not permission to relax genesis validation.
After using the existing one-note valueless fixture, the affected case passed in
0.04s: missing parameter paths and nonexistent receiver remain unopened when
the bound response is truncated. Service94ms/CPU71ms/peak8.3M/swap zero. No work
or payment proof was generated and no native receiver store was opened.

Exact final source SHA-256:
`7c22cb3fd24eee48848ea335fe0344f1e569aae7c8b0c9f5c1481a411a9ebd85`.
Final production ELF SHA-256:
`2595239b95bd2f3b43299d862939d62a4864fdf03d6399c1bccef03b1a1c560c`.
Final test ELF SHA-256:
`e6e67179aededfd161a99d23de4235a0abbbe418597fc3321f751fd0de0b1bd1`.
Locked/offline Rust1.93 final test compilation passed in service3.067s/CPU3.044s/
peak147.5M; production compilation passed in service2.047s/CPU2.040s/peak133.5M;
both swap zero, compiler-only Tasks16/3GiB/one CPU. The first successful compile
was not repeated merely because its path collector failed; corrected fixture
source then justified the narrow subsequent compiles. Earlier frozen ELFs and
failure receipts are preserved. Synthetic tests remained Tasks4/3GiB/noSwap/
one CPU/60wall/30CPU, no network/capabilities, strict read-only system/home,
only the owned64MiB tmpfs writable. No Mac build/test/proof/format execution.

Changed-production-span Clippy had zero findings;162 outside-span baseline
findings were kept separate. That lint ran before the test-only fixture fixes;
the production command paths did not change afterward. It is not a whole-source
or whole-project clean-lint claim.

Final build receipt SHA:
`f88fed57af696035d7dcd08200a9342063d5155b90942ddb15bedd700af38a5a`;
corrected partial-case receipt SHA:
`017665ca4c6c61089dcf8b4955379eea60ab20836565aab4a6b964693eea3947`;
production-span lint receipt SHA:
`0e89a7bf911278c4cfef3df99852093efa6f59d4a76290eab4c855e105a14991`.

## Concrete unmet integration gate

Native execution of these new commands and host-separated interrupted delivery
remain pending at this source milestone. The frozen next check uses only eight
existing public carriers in two four-carrier frames, not another3080 replay.
The static public source is `/var/tmp/silknode-public-range-source.TYUMUg` on
existing host `v2202607383485485163`; it serves bytes through existing authenticated
SSH only. All native work runs on the research receiver
`v2202610383485532100` (`89.58.59.175`), in a new exclusive owned directory on the
existing64MiB task tmpfs. No new port, service, host, spend or secret transfer.
The Mac only orchestrates SSH/source custody; it performs no native computation.

The exact pinned3080-row public manifest is
`c0a8902985b35bdf8ad152d8d959104842db05ca5aec418bcaaa8bd14c622d2d`.
Source frame0/count4 is5687 bytes, SHA
`a59dd65507c3ceef658a0e494fd7401717acf8d66b18e8ec28b4518a66970fd0`;
frame4/count4 is2897 bytes, SHA
`791f6f97ab5003713f812459f7b295b5834fcea3c7c42d45100cd21855e77dd0`.
The second transfer is cut after1448 bytes by terminating only the owned SSH
client once the receiver confirms partial delivery. A fresh complete transfer
uses a different file; the incomplete response is preserved. Static refusal must
leave every receiver file byte unchanged. Only then can a fresh pinned process
derive4, reject a replayed start0 request, and ordinarily ingest4..8. Final cold
query must derive8 with no previous recovery or duplicate admission.

Eight one-shot phases each have Tasks4/3GiB/noSwap/one CPU/<=120wall/60CPU, a
shared1200wall deadline and durable outer intent; total planned phase CPU ceiling
480 seconds. Existing vertex2CPU/5wall and checkpoint10 budgets are unchanged.
Native failure preserves owner/markers/intent and prohibits later phases.
Only successful receiving-process HEAD reports are saved outside its node store.
No source cursor/count decides what the receiver skips.

Frozen phase helper SHA:
`a158f60cce296cfe12387ec813cb70e2786997d336fd25e453bfde477df2e738`;
public-byte collector SHA:
`d9c79ba960deb03408e8f5930b24ee4645372646e7efe933342e26b3d6f2f7b4`.
SSH/static distribution can demonstrate this limited core receiving path, not
native P2P transport acceptance, two independently operating consensus peers,
concurrent branches/churn, sustainable operation beyond4096, privacy/speed,
wallet recovery or production/release readiness.
