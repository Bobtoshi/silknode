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
  silk-f04-relay            two-relay transport and producer handoff
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
