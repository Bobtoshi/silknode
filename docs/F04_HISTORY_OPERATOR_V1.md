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

## Frozen SSH integration plan

Native execution of these new commands and host-separated interrupted delivery
were pending at source milestone `a4dc0c1`; the subsequent result is below.
The frozen check uses only eight
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

## Completed bounded SSH/operator sequence

The exact published source `a4dc0c105cb1cd1898a2a9919740f951a53b192f` and frozen
production ELF above PASSED the one planned eight-phase sequence. This is an
actual host-separated SSH static-source/operator receiving path, not two native
consensus peers or P2P acceptance. The source and receiver host names differed;
all native work remained on the isolated research receiver. No new listener,
service, spend, mining, payment proof generation or secret transfer occurred.

The manifest and both full frames were delivered from the static source host
through existing SSH. After ordinary first-batch admission, the receiver was
Ready with four records and external HEAD
`6f956cb1128db732f57e2f1b16b5847ad0efc1de067ad592a186bf2a28922c84`.
The second stream was cut by terminating the exact owned SSH client only after
the receiver confirmed1448 bytes. SSH exited255; the bounded byte collector
preserved those bytes and exited0, NOT native acceptance. Incomplete SHA:
`6d14bb5efd8c66441fe3ca3424f6a7f0980430ff301e80a146897ebc1a852714`.
The CLI rejected it as truncated before parameters/store opening. An external
before/after digest inventory confirmed every receiver-store file byte unchanged.
No failed native job was created or retried.

A fresh pinned process derived4 without previous recovery or clock flush. A
start0 replay request was then rejected because it was not the receiver-derived
prefix; no duplicate admission or new HEAD followed. A separately delivered
complete second frame used a new file, preserving the incomplete evidence.
Four more ordinary admissions/reconciliations produced Ready8 and one checkpoint.
A final fresh pinned process again derived8 and reproduced the same semantic
report and HEAD, without previous recovery:

- HEAD: `a516d0e9114aaeb3f069ae9322b85d2e9012f26453b2c8a377098e67b946b9f1`.
- Checkpoint1: `3caf1cfe23125f98eafb5ac8d7f0b89331e20ad1d077c4517dfb8b204c66ae96`.
- State digest: `eb187fc8220b31814c44c0b9fe7f77fc5920a13214aadc2b4dbf49fd75bcdd38`.
- Public report: leaves4/pool299/burned1/eligible-cut0, equal before/after cold
  reopening. These are valueless fixture results, not production monetary rules.

All eight phase checks passed; two nonzero CLI exits were the expected truncated
and wrong-prefix refusals. Combined systemd service CPU15.258s/wall15.497s;
reported peak at most324.2M and swap zero. These sums exclude SSH orchestration
and transfer time, and are not a network throughput or privacy benchmark.
The unchanged phase/per-vertex/checkpoint bounds were respected. No full3080
replay was repeated or earlier full-history result transferred to this ELF.

Read-only closeout confirmed UID1000 processes reaped, all eight outer intents
closed, no receiver ACTIVE_JOB/ACTIVE_REPLAY, four earlier failed64-byte markers
preserved, protected original image size/blocks/mtime/ctime unchanged, and only
the original SSH listeners on the research host. The exact owned local SSH
clients and source transfer command were also reaped. New successful receiver,
static source and incomplete public response remain preserved; no repair or
adoption of any failed historical owner occurred.

Combined result/closeout receipt SHA:
`e7e59a32c691e176a632eece1de7a250ac1d8f110ee9439fb45ac967afdabf34`.
Final cold phase receipt SHA:
`db52951bf78a5625946cd281e4a39f01c68dd995e8b475a2eb828ee536596d9c`.
Partial refusal receipt SHA:
`a4bfb1303d51aa19ce4bdcff7520caab4df035f46353757215f016abeca87298`.
Interrupted transfer receipt SHA:
`b4c6be258f065a8bf606e324e1a0597b949b02b090674c1b918fa7d746f6b131`.
Mac public-byte FIFO orchestration script SHA:
`a66076efc6851b287dbc445ddb83de6189e601c5b54382b638a4fc97e67238fb`.

Native P2P transport, continuous competing peers/branches/churn, full3080 prefix
cost, sustainable history beyond4096, wallet recovery, practical speed/privacy
and whole-core/security/release acceptance remain UNPROVEN. Source-only review
or this bounded receipt does not independently establish those claims.
