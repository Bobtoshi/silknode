# F0.4 native historical ingestion and separate restart gate

This is bounded private, valueless implementation evidence, not whole-core or
release acceptance. It exercises ordinary validation of an existing public
historical fixture; no mining, new payment proofs, private keys, imported node
store or imported validity are used.

## Exact tested implementation

Private signed source: `4ec630eac02790563abd8ad2b0709d9f5d8483ca`.
Public signed source: `ab90cbb7b642cf0f36e55e382d922fb0f5d046be`.
The [header-facts correction](F04_GRAPH_HEADER_FACTS_V1.md) retains only already
qualified operation-owned parent/work fields. API, consensus/wire/commitment
bytes, mandatory checks, module boundaries and release defaults are unchanged.

Exact Linux ELF SHA-256:
`71e4b31c7fe75fceb29ece752629ac1552c4d236f4c2b2b6944ceb6526f6ea2d`.
Node graph source SHA-256:
`9881e770ed4aedc5630e941c4c3d10a60157955954c5754e60c9e88f7af44783`.
Order library source SHA-256:
`3c637b83d0c37d831e6473c7d9f806e72715c4e2bba41619d93cd8a40a67013b`.
Existing runtime workspace custody qualifies 428 tracked source files against
the public28 inventory plus these exact compiled overlays; its detached Git
HEAD is not falsely presented as the new public source HEAD. Three absent
noncompiled documents are disclosed in the preflight receipt.

## Preserved failures and necessary volume correction

Earlier source26 and source28/source29 failures remain described in
[the graph-order facts report](F04_GRAPH_ORDER_FACTS_V1.md) and
[the header-facts report](F04_GRAPH_HEADER_FACTS_V1.md). Their failed owners,
markers and evidence have not been reopened, repaired, adopted or cleared.

The first source30 full run (v3) cleared the previous candidate2449 CPU refusal
but stopped at ordinal2759/candidate2760 with
`Unavailable("retained vertex index page publication failed")` and
`first_cooperative_budget_failure=None`. Last printed completed batch:2752.
Carrier SHA-256:
`01e20ad7767d42e98a6f633e7a21b7138567259c7b19b88ac013699c9677bd2c`.
Service1319.441s, CPU1130.168s, peak1007M as reported by systemd, swap0.
Cold replay did not start.

Read-only filesystem metadata found all65536 inodes used, zero available, while
629014528 bytes remained available. The original publication error does not
retain raw operating-system errno; this is observed inode exhaustion with spare
bytes, not an exclusive phase profile or a core inode-resilience test.
Its failed64-byte ACTIVE_JOB remains preserved with mode0600/UID1000.
Diagnostic receipt SHA-256:
`51c658402dbae182a3c698f20ecffd401725f43f2958c75f2a2b17a5d5d82fde`.
Native result SHA-256:
`bde3b07a052b0f5e17b07ddc7d0fd09c8d54f4eda5edccfff533e4aa52b18129`.
Pair result SHA-256:
`f6a9b61b3a420695d18d2d0b33d23a8811e818d2d607672aa33a1b91369a7943`.

One fresh v4 image corrected this diagnosed fixture geometry, not the core
protocol: explicit131072 ext4 inodes and>=130000 free before dispatch, within
the SAME1073741824-byte image cap. Actual filesystem1003925504 bytes,
initial available933171200 bytes/131059 inodes, nodiscard/nosuid/nodev/noexec.
The exact source/ELF was unchanged; no rebuild or repeated synthetic fixtures.
Old images and the protected original join image remained untouched.

## Actual fresh ingestion PASS

The exact ignored test
`node::historical_tests::historical_public_ranges_ingest_and_reconcile_fresh_node`
passed on v4. All3080 existing carriers went through ordinary receiving,
mandatory work/proof/parent/order/ledger validation and finite reconciliation.
Assertions checked Ready, no recovered_previous,3080 executed/checkpoint385,
the original independently pinned state/checkpoint claims, cut/leaves/private
counters/output count and remaining original history/generation horizons.
Each carrier also required Ready and no ACTIVE_JOB before the next carrier.

Test1539.79s, service1539.838s, CPU1317.549s, peak1G as reported by systemd,
swap0. Original vertex2CPU/5wall/checkpoint10 and4096history/20000generations
limits were not raised.

The receiver's fresh HEAD, explicitly different from historical source HEAD:
`97af84814b77862aba31583e505719b7f1f55dd5bcf1e7ae7af83853583d8901`.
Derived order SHA-256:
`61f49505f85afeaf624b74e031fc5f2facdd4e1790da327d5ca09fd29add9f9a`.
Derived public-ledger SHA-256:
`7f02993fe649cbeffd3455983708ef537c025e7aabd030715bc84767ced9d6d5`.
First-process stdout SHA-256:
`008d70e75a9265f127c4ad15ceec1311a0f33d87d255a250ff4fbf8af7e5bfea`.
First-process result SHA-256:
`4a57f95dee28e11395c55fab4556df42ecae2165eb2b41d1101880637dc58b16`.
Externally frozen receiver-pins receipt SHA-256:
`aa9b443209433c6919e382ce01e65888f76b59d31b6ea381d075ac62affe1a8c`.
The pins were retained in root-owned evidence OUTSIDE the tested filesystem,
from exact successful output, not imported from expected files inside the store.

## Separate cold replay PASS

The first process ended before a separate OS process began the exact ignored
test `node::historical_tests::historical_public_history_second_process_cold_parity`.
It receives only the externally frozen HEAD/order/public-ledger pins, performs
ordinary full semantic retained replay and requires complete state/order/ledger
parity plus exact-repeat no-new-credit behavior. It passed with3080 vertices,
385 checkpoints, the original claimed state freshly derived, and exact repeats
at the beginning/end of the fixture yielding AlreadyKnown without new credit,
changed HEAD/ledger or an ACTIVE_JOB. It does not claim wallet-key recovery from
public carriers.

Test1325.83s, service1325.877s, CPU1294.455s, peak827.9M as reported by systemd,
swap0. Cold-process result SHA-256:
`fde3c1ee279f6a3f0f5d14a534f27bf7de81958d1359c47a4c58ffb06728dc8e`.
Cold stdout SHA-256:
`39d15d09920fe6f66f1cb05dfe0b06d0906ab914d84977812938918c8f6c67b6`.
Cold stderr SHA-256:
`3ad449667f1802f883411422ad674a1ceedb32a25490ac4583ef51e0b2891b35`.

The combined first/cold gate PASSED. Collector elapsed2866.009804785s;
the sum of reported unit CPU use was2612.004s, below3300s, with no swap.
Pair result SHA-256:
`84e7ceb556cad8dd29d1fecd7481a99eead2670a5521c9bed2413a9bc42f9d49`.

Read-only closeout confirmed UID1000 processes reaped, no ACTIVE_JOB or
ACTIVE_REPLAY in the successful owner, all four earlier failed ACTIVE_JOB
markers preserved, only original SSH listeners, and protected original join
image size/mtime/ctime/blocks unchanged. Successful filesystem had559648768
bytes and54335 inodes available. No additional replay or repair was performed.
Closeout receipt SHA-256:
`6ac84f86822e66d1bd8b55031f1d973fe4c01034ba18efd7fe76cf11fe4a3caa`.

## Shared containment and remaining boundaries

Both processes use3GiB/noSwap/one CPU/four tasks, no capabilities/network/listeners,
strict read-only system/home, only the newly capped mount writable, no automatic
restart. ONE shared3600s monotonic wall/3300s CPU allowance gates both; the cold
process receives1980 CPU seconds and remaining wall time after reserving1320
seconds for the conservatively rounded-up first-unit CPU usage. No budget refill.
Frozen plan SHA-256:
`b5b81f45d72b82462dc6a99096e3ee0705db27cdbd93214c7f9e74e58039154f`.
Collector SHA-256:
`0fa96e63c9745cad88d212f1254f16e990187a396461c61822c08e9fee5ccc20`.

This is native ingestion/restart evidence on the exact fixture and source, not
independent whole-core acceptance. This is not a sustainable/unbounded-history
claim, arbitrary reorg proof,
two-host transport/churn acceptance, practical-speed or privacy proof, independent
whole-core/security/release acceptance, value activation or live deployment.
Whole-core readiness remains UNPROVEN. This is a foreground development gate,
not a recurring scheduled job.
