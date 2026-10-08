# Architecture

SilkNode separates private wallet material from the public data checked by a
node. F0.4 is the current experimental integration profile; the crate names
retain that version rather than implying a stable production API.

```text
Private wallet / scanner
  silk-f04-wallet + silk-sapling-f04
        |
  silk-f04-client::v1       explicit submission ownership
        |
  silk-f04-relay            ordinary transport; optional R2 / three-relay IM3
        |
  silk-f04-node             full admission -> DAG -> sealed cuts -> store
        |
  silk-order + silk-pow + silk-randomx + typed profile/kernel interfaces
```

This is a component map, not a claim of independent operators or an anonymity
proof. The quick start exercises only genesis, scanning, witnesses and empty
store creation—not the complete path shown above.

## Module map

| Crates under `prototype/crates/` | Responsibility |
| --- | --- |
| `silk-sapling-f04` | Fixed-shape transaction codec, Sapling proofs/authorization, encrypted recovery, authenticated parameter loading |
| `silk-f04-wallet` | Wallet backups, intent journal and canonical reconciliation |
| `silk-f04-client` | Versioned local preparation/submission ownership; explicit offer and relay handoff |
| `silk-f04-relay` | Framing, cryptography, pinned TLS, schedules, journals and producer interfaces |
| `silk-f04-node` | Genesis admission, full-data DAG ingress/sync, state reduction, cuts, durable store and local scanner |
| `silk-f04-testnet` | Opt-in version1 zero-allocation public seed/miner adapter; TLS-bound full work-carrier sync, not wallet ingress |
| `silk-order`, `silk-pow`, `silk-randomx` | Graph order, work rules and pinned native work implementation |
| `silk-types`, `silk-profile`, `silk-bootstrap`, `silk-genesis` | Typed identities, versioned descriptors and supporting genesis/bootstrap definitions |
| `silk-kernel`, `silk-gate2` | Supporting execution/checkpoint descriptor and transition interfaces |
| `silk-local-platform` | Local platform support used by client/wallet integration |

Supporting transparent-profile descriptors are dependencies, not an alternative
public network activated by the quick start. Their eight files in
`prototype/spec/transparent-execution-v2/` are embedded as exact bytes. Editing
their prose or JSON can change descriptor identity.

## Boundaries for extensions

Build applications against explicit Rust modules and versioned types. The node
must still validate complete public inputs; receipt files, peer metadata and
wallet claims do not confer consensus authority. Spending/viewing keys remain
wallet-private. A relay delivery receipt is not settlement or finality.

Keep wire formats, domain separation, commitments and profile selection intact.
A different cryptographic suite or consensus rule needs a deliberately versioned
protocol change, not a drop-in adapter that silently changes validation.
Modularity does not mean arbitrary code can execute inside consensus.

The public-zero-v1 genesis is a closed, separately pinned empty-allocation
profile. It preserves the private genesis admission path, F0.4 rule bytes and
parameter commitments; it cannot authorize arbitrary zero-allocation profiles.
See [Public testnet V1](PUBLIC_TESTNET_V1.md) for its launch and transfer limits.

The `functional-lab` relay feature enables unqualified fixture scheduling and
is off by default. It is not production time/custody qualification. Local store
creation likewise does not establish a complete resource sandbox; deployments
need a separately reviewed execution environment. No deployment launcher is
included here.

## Optional three-relay IM3 boundary

IM3 is a separate experimental A→C→B composition, not the ordinary relay
path's new default. On Unix, the relay's `aip2-preparation` feature exposes
`aip2_im3`, `im3_schedule` and `im3_gate`; live functional construction also
requires `functional-lab`. Client `v1::im3_lab` and its R2 prerequisites require
the separate, default-off `r2-functional-lab` feature.

The original client receives the signed manifest on its existing A TLS link,
freezes its durable choice, prepares B then C membership proofs and writes in
its selected slot. A admits the full input train; C verifies the complete
middle batch before irreversible disclosure; B verifies the complete exit
batch. Signed readiness, producer acknowledgements, A authorization and B
release precede ordinary producer offers. Fixed authenticated cancellation
travels on original links, with no replacement connection or partial release.

The normal-wallet `offer_saved` API now requires an independent durable pin
retainer. It records `HandoffConsumed` before exporting one `SavedOfferV1`;
`offer_ready` is a no-export preflight and the old raw export is test-only.
Authenticated history retains both exposed-input nullifiers and note commitments
as exclusions, including when recovery changes a note's position/nullifier.
This is journal issuance control, not protection against a caller copying bytes
or coordinated rollback of the journal and its independently retained pins.

After a recoverable preparation/worker/verification failure in the enclosing
client driver, submission authority is destroyed. `Transport::into_cleanup`
consumes TLS state and record buffers while retaining the same nonblocking
socket and permits; `CleanupOnly` offers closure polling/finishing, no application
write or reconnect. The driver retains it to the original T+44 boundary or
detectable peer close. Early admission/manifest refusals remain separate;
panic, abandonment and process/host death are not masked. See
[handoff and cleanup limits](docs/IM3_HANDOFF_CLEANUP_V1.md).

`Im3RoundRunner::run_round` supplies scoped `Im3RoundPorts`; external callers
cannot directly construct the raw original relay owners. Durable sequence
claims precede dispatch, and terminal state fences subsequent rounds. Completion
means the original B release and cleanup completed, not node settlement.
Independent pin retention, trustworthy clocks, worker containment and actual
peer closure remain external obligations; Rust ownership alone proves none of
them. The IM3 experimental schedule has its own bounded round window and uses
the original two-CPU-second native budget, not a renewed proof-time lease.

See [IM3 implementation and limits](docs/IM3_EXPERIMENTAL_V1.md) for the source
map, omitted private controllers and separate evidence scopes. This change
does not activate a wallet network, alter consensus/payment bytes or change
the public testnet/mining defaults.

## Source and verification boundaries

The distribution retains first-party runtime source and a pinned curated
RandomX vendor tree, with compact test fixtures. Four upstream audit PDFs are
not redistributed; native RandomX algorithm source is unchanged. The old `silk-node` directory
contains only a shared public test-certificate generator, not another node
implementation. Operational configuration, private evidence/history, generated
parameter files and large legacy integration corpora are excluded.

See [RandomX provenance](prototype/docs/RANDOMX_V2_PROVENANCE.md) for its exact
source pin and limitations. Dependency identities/checksums are locked in
`prototype/Cargo.lock`; declared licence metadata is listed in
`LICENSES/dependencies.tsv`. Neither a lockfile nor a signed commit is an audit.
