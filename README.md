# SilkNode

An experimental, modular private-transaction DAG core written in Rust.
**Nonproduction software: no real funds, production deployment or anonymity
guarantees.** This is a source-only candidate, not a public network or a turnkey
node distribution. It has not received an independent security audit and does
not claim Monero-equivalent privacy or historical novelty.

The F0.4 modules implement Sapling-based shielded transfers, wallet recovery,
relay transport, DAG admission, sealed-cut state reduction and durable local
state. Supporting crates keep ordering, work, profiles and kernel interfaces
separate. Start with [Architecture](ARCHITECTURE.md) to find each boundary.

## Try a small local example

Use a **Git checkout**, not a source ZIP: the RandomX build verifies the exact
vendored Git index tree. Prerequisites are Rust 1.93.0 (pinned in
`prototype/rust-toolchain.toml`), Git, CMake, a C/C++ compiler and Make. The
documented path is checked on x86-64 Linux. Other platforms are not qualified
by this package. Allow several GiB for compilation and leave at least 4 GiB
free on the filesystem holding temporary state; the core refuses below that
margin. Do not disable its resource checks to make the example pass.

From the repository root:

```sh
cd prototype
CARGO_BUILD_JOBS=1 cargo build --locked --release \
  -p silk-f04-client -p silk-f04-node --lib \
  --bin silk-f04-local --example local-smoke
./target/release/examples/local-smoke
```

Expected final line:

```text
local-smoke: PASS (valueless genesis, recipient scans, witnesses, empty node store)
```

The example creates fresh encrypted genesis notes with values 10 and 20,
checks recipient recovery and Merkle witnesses, and creates then removes a
temporary empty node store. Fixture signing seeds are public test material,
not independent custodians. It opens no listener, mines no work, generates no
transfer proof and needs no proving-parameter download. It does **not** test
payments, restart recovery, distributed consensus, network privacy or sustained
operation. A successful build and this smoke check are not security acceptance.

The first build may fetch pinned registry packages. The same command supports
`--offline` after those exact packages are cached. No bit-for-bit binary
reproducibility claim is made.

## Explore and build on it

The Rust libraries are the extension surface; no privileged service or operator
account is needed to inspect them. Versioned adapters live in `offer::v1`,
`handoff::v1` and the client `v1` module. They do not let extensions bypass node
validation or change consensus bytes. There is no general-purpose plugin loader
or permissionless public-network launch in this package.

The `silk-f04-local` binary is a low-level explicit local tool, not a daemon.
Payment/proof experiments require the external Sapling ceremony files. Their
canonical URLs, lengths and full-file BLAKE2b-512 pins are in
[the optional acquisition tool](tools/fetch-sapling-parameters.py), matching
`silk-sapling-f04/src/parameters.rs`. From the repository root, Python 3.11+ users
can explicitly download them into a **new** directory:

```sh
python3 tools/fetch-sapling-parameters.py parameters
```

The tool refuses existing output directories, bounds download sizes and verifies
both complete files before installing them. Parameter bodies are not bundled;
this optional download path is not part of the checked offline smoke. Pins
authenticate bytes, not the ceremony's trust assumptions or an end-to-end
payment system.

## Contributing and limitations

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Tests and compact vectors are retained for inspection and focused work; some
proof/runtime tests require external parameters and separately bounded
execution. Large legacy corpus tests, deployment harnesses and internal
evidence are intentionally not part of this distribution. The quick start is
the package check, not a claim that every retained test was rerun.

Independent review, distributed adversarial trials, separate relay custody,
traffic-correlation analysis and sustained resource/performance measurements
remain necessary before stronger claims. Existing fixed horizons and platform
refusals are research limits, not production capacity promises.

Code and machine-consumed protocol material use [BSD-3-Clause](LICENSE).
Original documentation uses CC-BY-4.0; see [licensing scope](LICENSING.md).
[Third-party notices](THIRD_PARTY_NOTICES.md) retain upstream terms. These
licences do not imply endorsement or grant rights to the SilkNode brand.
