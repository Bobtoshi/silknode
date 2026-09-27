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

Supported path: x86-64 Linux, Rust 1.93.0, Git, CMake, Make, a C/C++ compiler,
Python 3.11+ for optional parameter acquisition, and systemd/cgroup-v2 resource
control. Use a Git checkout, not an archive: RandomX verifies its vendored index.

From the checkout root:

```sh
CARGO_BUILD_JOBS=1 cargo build --manifest-path prototype/Cargo.toml \
  --locked --release -p silk-f04-testnet
python3 tools/fetch-sapling-parameters.py parameters
./prototype/target/release/silk-f04-testnet identity
```

The acquisition tool verifies both complete ceremony files; the node checks them
again before replay. They are required by the existing API even for empty
carriers. No proving-parameter bodies or secret keys are bundled.

Use a **new private state directory on a dedicated, capped filesystem**
(maximum 16 GiB). Leave at least 4 GiB free on the separate host filesystem
named by `host_margin`; do not defeat the checks or point it at the capped
volume. The store pauses at its existing 14 GiB accounting threshold and
4,096-vertex reference horizon. This is not indefinite operation.

Copy [miner.example.json](testnet/public-v1/miner.example.json), replacing every
`/ABS/...` path with a real absolute path. Create the state parent and sibling
`pins` directory mode0700, owned by your unprivileged user. Do **not** pre-create
`store`, `pins/head` or import another operator's store/pin. Generate a fresh
public attribution tag with `openssl rand -hex 32`; this is not a spending key.
Keep the JSON config local. Leave the pinned domain, seed and certificate fields
unchanged when connecting to the bootstrap seed.

Run these one at a time, with the same config and state directory:

```sh
# Set these to your checkout binary and edited configuration:
testnet_binary=/ABS/checkout/prototype/target/release/silk-f04-testnet
testnet_config=/ABS/miner.json
run_testnet() {
  systemd-run --user --scope -p MemoryMax=4G -p MemorySwapMax=0 \
    -p TasksMax=4 -p CPUQuota=100% \
    "$testnet_binary" "$@" --config "$testnet_config"
}
run_testnet init
run_testnet probe
# --count follows --config for the mining command:
systemd-run --user --scope -p MemoryMax=4G -p MemorySwapMax=0 \
  -p TasksMax=4 -p CPUQuota=100% \
  "$testnet_binary" mine --config "$testnet_config" --count 8
run_testnet sync
```

A resource-control failure is not permission to run an unbounded fallback.
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
