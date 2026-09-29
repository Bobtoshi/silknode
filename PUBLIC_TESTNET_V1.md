# Public zero-value testnet V1

An opt-in **mining-only experiment**, separate from the private F0.4 profiles.
No mainnet, real assets, premine, sale or transferable mining rewards.
Genesis contains zero notes and zero allocation. Existing public mining credits
are attribution counters, not coins and cannot fund a wallet transfer.

This successor is **not in the published `v0.1.0-alpha.1` tag**. Until separately
reviewed and published, the current public alpha checkout lacks these commands.
Use the reviewed successor Git checkout when it is made available; do not assume
a reachable seed means its new source has already been released.

## Build and configure a connecting miner

Supported path: x86-64 Linux, Rustup with Rust 1.93.0, Git, CMake, Make, a C/C++ compiler,
Python 3.11+ for parameter acquisition/preparation, and systemd/cgroup-v2 resource
control. Use a Git checkout, not an archive: RandomX verifies its vendored index.

From the checkout root:

```sh
CARGO_BUILD_JOBS=1 cargo +1.93.0 build --manifest-path prototype/Cargo.toml \
  --locked --release -p silk-f04-testnet
python3 tools/fetch-sapling-parameters.py parameters
./prototype/target/release/silk-f04-testnet identity
```

The acquisition tool verifies both complete ceremony files; the node checks them
again before replay. They are required by the existing API even for empty
carriers. No proving-parameter bodies or secret keys are bundled.

### Prepare a first join on Linux

The explicit [preparation helper](tools/prepare-public-testnet-v1.py) replaces
manual filesystem/config placeholders. Inspect it before running with sudo.
It needs an existing non-root account, cgroup v2/systemd, util-linux and
e2fsprogs. It installs no packages, accounts, persistent services, firewall rules
or boot-time mounts, opens no listener and makes no network requests.

```sh
# From the checkout root, as your ordinary Linux login user:
sudo python3 tools/prepare-public-testnet-v1.py \
  --destination /var/tmp/silknode-first-join-v1 \
  --owner "$(id -un)" \
  --binary "$PWD/prototype/target/release/silk-f04-testnet" \
  --parameters "$PWD/parameters" \
  --store-gib 4 --accept-public-zero-value
```

The destination must not exist. The helper physically reserves and formats
**only its newly created regular image file**, mounts it with nodev/nosuid/noexec,
creates private sibling store/pin locations and a concrete pinned config, and
generates a public attribution tag. It verifies both entire parameter files and
the bootstrap CA before creating anything. The copied ELF is your selected
locally built binary; its printed SHA256 identifies bytes, not release approval.
The account owns node data, not the backing image or copied executable/parameters.

Run the two exact commands it prints, in order: **init, then sync**. They use
transient systemd jobs with your non-root UID, 4 GiB RAM, no swap, four tasks,
one CPU, a 900-second lifetime and no listening sockets. `sync` discovers the
pinned seed and independently revalidates its full genuine-work history; it
does not import a peer's store or accept a peer's checkpoint as proof.
An optional, separately printed `mine --count 1` command submits genuine work
only when you explicitly run it. No mining occurs during preparation or sync.
Commands/config are retained in `preparation.json` and `volume/node/config.json`.

Preparation refuses existing directories/state, malformed inputs, insufficient
backing reservation or host margin. A partial failure retains its new files for
inspection; it does not delete, overwrite or silently retry. Once all node jobs
have ended, the printed unmount command retains every file and note of state.
For later remount, use the same `store.ext4` with `loop,nodev,nosuid,noexec` at
the same `volume` path; never format it again. No automatic boot mount is added.

Advanced operators can still use [miner.example.json](testnet/public-v1/miner.example.json)
with an already capped filesystem and absolute paths. Keep at least 4 GiB free
on the separate host filesystem; the image may be 1–16 GiB. Existing 14 GiB
accounting and 4,096-vertex horizons remain, not indefinite-operation promises.
A resource-control failure is a STOP, not permission for an unbounded fallback.
Ordinary mining uses current wall time, genuine interpreted-light RandomX,
initial work1 and the unchanged parent-local DAA. The CLI paces successive
attempts 40 real seconds apart, not simulated time. It downloads full history,
independently validates it, submits complete work-bearing carriers, and checks
the seed acknowledgement against locally derived state. Eight eligible
vertices are needed for the first checkpoint. Graph admission alone is not
settlement; a checkpoint is not a production finality guarantee.

Normal restart uses the separately retained local `pins/head` and fresh
replay. Never copy store/HEAD into that pin to silence a failure. An interrupted
operation, missing/mismatched pin, uncertain durable write, exhausted resource
budget or unsupported platform is a STOP, not automatic recovery authority.

## Bootstrap identity

- Seed: **152.53.113.247:28444**, TCP, TLS1.3, ALPN `silknode-zero/1`.
- Network name: `silknode-public-zero-v1`; version1; magic ASCII `SNZNET01`.
- Genesis time: `1790467200` (2026-09-27 00:00:00 UTC).
- CA: [ca.der.hex](testnet/public-v1/ca.der.hex), hex-encoded public DER certificate.
- CA DER SHA256: `3b45cde0f3bd37920bd376d22e66f4039620b943d511da34daced606e0433d4a`.
- Seed leaf DER SHA256: `20f2e023298a8d59678ec63b22a4a6e11929de52300461a995d032a8c2dd480c`.
- Seed certificate expires 2027-03-26 20:18:13 UTC; rotation requires an explicit new pin.

```text
network = 18c46dc1c8cdc0d1f3d8167b34898c73a942cdb660f10c84190b52b5ab4c8b25
chain   = a7d86fe6b8def80d7f1d9d32939b6fac7fda068eba05122bb8138d97568534d4
genesis = 68842a91e3c3184a985c557f7ea8bf5e2bc1e35f02f6d94942c7ed7a3a2194e6
domain  = 3e156fe886be5b82188b5af94f48e4dac0017a8c061298ae7d136438c3bc987e
wire    = 9f0c99bc6d025ee6d0716dce183ab4d564a651c1ca30a042f588773a26e666a3
bundle SHA256 = 4e799358037512df91e2b97208ef38d21efd81c9d91006c48fe7269911166ef2
```

The executable checks the entire deterministic genesis bundle and context pins.
Its closed constructor has new descriptor/allocation magics; it does not relax
old allocation attestations or change existing private genesis/consensus bytes.
TLS checks CA, certificate validity, IP SAN and the exact leaf digest. Wrong
network/chain/domain/version/magic is refused before vertex admission.

## Run your own seed; module boundary

Use [seed.example.json](testnet/public-v1/seed.example.json) with a fresh,
dedicated TLS key/certificate and your own advertised IP:port in `seed`.
Replace its CA path and exact leaf pin accordingly; the certificate needs that
IP SAN and serverAuth. Do not request or reuse the bootstrap seed's private key.
Create a new store with `init`, then run `seed --config /ABS/seed.json` under a
dedicated unprivileged, resource-capped service. Publish your public certificate
pins to connecting miners. Serve only one necessary TCP port.

The versioned adapter offers status/bootstrap advertisement, bounded full-range
export and full work-carrier submission. Each TLS connection has one request,
bounded frames and one nonrenewable 45-second I/O window. Node admission still
performs all consensus/work checks. It is **not** raw wallet-envelope ingress,
a relay bypass, an automatic peer mesh or a general-purpose plugin loader.
Operators can stop, synchronize and reopen; cross-seed gossip is not automated.

This first bootstrap is one seed. The launch check uses one separately started
miner with a different OS identity/store on the same host; it cannot establish
operator independence or decentralization. TLS does not hide peer IP addresses.
No network-privacy, adversarial-load, performance, long-history/maturity or
production-readiness claims follow from this bounded launch check.

## First-join evidence and limits (2026-09-29)

The five focused, non-privileged checks pass with
`PYTHONDONTWRITEBYTECODE=1 python3 tools/test_prepare_public_testnet_v1.py`.
A fresh 4 GiB setup on x86-64 Linux completed the printed `init` then `sync`
commands over pinned TLS: eight genuine-work vertices were locally verified,
eight executed and checkpoint 1 was derived, with zero initial allocation.
The existing seed process and retained head were unchanged; no work was mined.
This reused the existing Linux binary (SHA256
`a210eff0c5cad3144ec14b49ec744b5dbb8c32389177edbf8d2d5171a150df6e`),
not a new build or a new release qualification.

That check exposed lazy ext4 initialization releasing backing reservation.
The helper now completes initialization before reserving and checks again at
completion. A separate fresh preparation with the corrected format options
retained at least 4 GiB of allocated backing through mount and unmount. The
network sync was not repeated after this formatting-only correction.

This was fresh state on the same operator's host as the seed, not an independent
participant or separate-host onboarding acceptance. Other distributions,
interrupted preparation and long-running operation remain **UNPROVEN** by this
check. No privacy, decentralization, transferable assets or release readiness
is established. Source publication remains a separate decision.
