# Getting started

SilkNode is nonproduction research. Use only fresh, disposable, valueless local
state. A source update is not deployment, privacy acceptance or a supported
public wallet service.

## Small public example

Follow the [README local-smoke commands](README.md#try-a-small-local-example).
They use a Git checkout, the pinned Rust 1.93.0 toolchain and the documented
Linux/native build prerequisites. The smoke example needs no proving-parameter
download and opens no listener. It checks genesis recovery, witnesses and an
empty node store, not a payment or an anonymity journey.

The separately opted-in zero-value adapter has its own
[testnet guide](PUBLIC_TESTNET_V1.md). IM3 is not integrated into that adapter;
this source update changes neither its launch policy nor mining defaults.

## Inspect optional research components

Start with [Architecture](ARCHITECTURE.md), [status](STATUS.md) and
[IM3 implementation and limits](docs/IM3_EXPERIMENTAL_V1.md).

- Relay `aip2-preparation` exposes Unix-only R2/IM3 profile, verifier and gate
  interfaces. Functional runtime construction additionally requires
  `functional-lab`; both features are off by default.
- Client `r2-functional-lab` exposes `v1::r2_lab` and `v1::im3_lab` and opts into
  the relay's two research features. It is off by default.
- Explicit examples are `f04-relay-lab`, `aip2-r2-integration`,
  `aip2-r2-timed-lab` and `aip2-client-dispatch-lab`. These are lab entry points,
  not ready-to-run IM3 deployment commands. Their required features are declared
  in each crate's Cargo manifest; their modes and inputs are in source.

The legacy `f04-relay-lab` example expects an explicitly isolated `/work`
sandbox layout, including public context, private test secrets and parameter
mounts. No sandbox launcher is bundled. Those generic mount paths are not a
host installation recipe; do not create or expose that layout on a live host.

Lab paths need deliberately supplied fresh fixture directories, signed matching
config/profile/manifest context, public verification keys, public test TLS
material and independently retained local claim pins. Payment paths also need
the [pinned external Sapling parameters](tools/fetch-sapling-parameters.py).
Membership-proof paths require a separately supplied compatible proof helper
and setup, plus an explicitly bounded worker runner. No accepted production
membership setup or helper package is bundled. Do not substitute a caller's
success flag for native verification or weaken resource/time refusals.

The retained two-client orchestration is in ignored Rust harness tests, not a
public end-to-end launcher. It requires external fixtures and contained worker
jobs. The public checkout excludes private controllers, readiness/fault
supervisors, challenge credentials, evaluator truth/reveal maps, proving keys
and raw evidence. It therefore cannot reproduce all private demonstrations on
its own. Do not use `--ignored` indiscriminately: proof, mining and cold-recovery
tests can be expensive and require separate finite execution planning.

No builds, tests, native runs or proofs were executed for this IM3 public export.
The original private executions are historical evidence for their exact source
and fixtures, not fresh execution acceptance of this curated package. Existing
quick-start evidence belongs to its preceding public checkpoint.
