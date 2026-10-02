# F0.4 pinned multi-source catch-up, version 1

This local networking increment removes the requirement that one configured
seed be reachable for every catch-up. It is opt-in, zero-value full-carrier
synchronization, not permissionless discovery, private payment submission,
production readiness or whole-blockchain completion.

## Operator interface

The original configuration and single-source commands remain valid. An explicit
peer manifest adds one to seven independently selected endpoints to the original
primary, for at most eight sources. Only `sync` accepts the extra option:

```sh
silk-f04-testnet sync --config /absolute/node.json --peers /absolute/peers.json
```

The additional manifest is separate from the unchanged node-config-v1 schema:

```json
{
  "schema": "silknode-public-peers-v1",
  "peers": [
    {
      "endpoint": "192.0.2.10:28444",
      "ca_der_hex": "/absolute/operator-selected-ca.der.hex",
      "certificate_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

The example endpoint and certificate hash are placeholders, not a usable peer.
Obtain and verify each real CA/leaf pin independently. Existing certificate-chain,
IP-name, exact leaf-certificate and network-hello verification still apply.
There is no trust-on-first-use, peer-supplied enrollment, DNS expansion, fallback
to unverified TLS, or replacement of an operator's node/wallet keys or local pin.
Malformed/duplicate endpoints, relative paths, unknown fields, invalid hashes,
unsupported schemas and excessive source counts refuse before opening the node.

## Receiver and failure contract

- Each pinned source is attempted at most once per invocation, primary first.
  Unavailable transport, rejected identity, malformed ranges or nonmatching
  status claims can move catch-up to the next explicitly selected source.
- A cursor is source-local. A switch restarts that source at range zero; neither
  equal graph sizes nor an old peer's offset establishes prefix equality. Exact
  repeated carriers still pass `Node::ingest`'s byte comparison and AlreadyKnown
  path, without a new admission job or unnecessary retained-pin replacement.
- Entire range framing is checked before any member is submitted: one to 32
  nonempty carriers, at most 90,000 bytes each, no truncation or trailing bytes,
  and the existing 4,096-vertex reference horizon. The horizon is not increased.
- Every new carrier still enters the ordinary local work/proof/parent/clock/
  consensus admission and reconciliation route. No remote checkpoint, claimed
  work, saved verification flag or received store grants authority.
- A storage, resource, clock, reconciliation, retained-pin or uncertain ingress
  failure stops the whole invocation. It is not reclassified to obtain a fresh
  allowance from another peer. In explicit multi-source mode only, a definite
  ordinary ingress rejection (`Invalid`, Sapling `Encoding` or `Crypto`) may
  abandon that source after the receiver remains READY with exactly the same
  local head, graph count and state digest, and the independent retained pin
  still matches. Apart from the scoped missing-parent case below, other error
  variants remain local STOPs. Settlement failures
  are never peer failures. Original single-source ingress failure behavior is
  unchanged.
- A definitely rejected carrier's SHA-256 is retained for this invocation. The same bytes
  from another source abandon that source before another admission attempt;
  no rejected job receives renewed work/proof time. At most eight rejection
  hashes are retained, one per attempted source. The rest of a rejected batch
  is not ingested. Different valid data from another explicitly pinned source
  can continue from the already accepted local prefix.
- A source that supplies a child before its locally missing parent may also be
  abandoned in explicit multi-source mode. The ordinary receiver must report
  exactly `Unavailable("missing admitted vertex")` and pass the same healthy,
  idle, READY, unchanged head/count/digest and independent-pin checks. This is
  unavailable dependency data, not a verdict that the child's protocol is invalid.
  No admission marker/native work may have started. These bytes are NOT added to
  the invalid-carrier cache: another source can supply parent then child through
  ordinary ingress. Uncertain jobs and all other history errors still STOP.
- Completed, locally accepted prefixes remain retained after source loss or
  exhaustion. There is no rollback, store replacement, automatic retry of an
  uncertain job, or adoption of a remotely supplied local-head pin.
- Multi-source operation has one cooperative 1,800-second allowance shared by
  all peers and exchanges. TCP connection and existing 45-second I/O windows
  are tightened to its remaining time. Source changes and partial progress do
  not renew it. It is checked before each new local ingress. An already-started
  local job retains its ORIGINAL native budget and may finish past the outer
  cooperative deadline; this is not an independently qualified hard whole-process
  timer. Original single-source timing and native job limits are unchanged.
- Success requires the existing local state/count/checkpoint comparison with
  the chosen source's advertisement. That comparison is not proof of an honest
  advertisement, a complete remote inventory, identical noncanonical graph
  evidence, or an independent operator. Divergent histories may remain retained
  without any source matching the union's status; this increment is failover,
  not a complete multi-producer gossip/discovery protocol.

## Ordinary module access

`silk_f04_node::sync::RangeBatchV1` is a public, versioned borrowed framing
adapter. Its outputs are explicitly UNVERIFIED bytes, not `VerifiedVertex`,
ledger authority or provenance. Third-party transports can use the same adapter
and ordinary `Node::ingest` API as the bundled client. The additional source
selection/transport driver remains outside consensus and the private relay.

## Reproduce focused checks

Use a Git checkout, Rust1.93.0 and OpenSSL. The ordinary public-workspace
binary still builds using the command in [Public testnet V1](../PUBLIC_TESTNET_V1.md).
For just the non-node driver/enrollment/TLS checks, run from the checkout root:

```sh
CARGO_BUILD_JOBS=1 cargo +1.93.0 test --offline --locked \
  --manifest-path prototype/Cargo.toml -p silk-f04-testnet \
  --bin silk-f04-testnet -- sync:: peers:: --test-threads=1
```

The separate focused target additionally checks the compiled public range API:

```sh
CARGO_TARGET_DIR=prototype/target cargo +1.93.0 test --offline --locked \
  --manifest-path prototype/checks/peer-sync-v1/Cargo.toml \
  -- sync:: peers:: --test-threads=1
```

This checked-in target compiles the actual testnet source and links the actual
node library. Its external range tests use only the public compiled API: no
private implementation or test-source imports, no alternate admission engine.
Its 162 locked package identities/versions/checksums are a subset of this public
package's 198; no dependency identity, checksum or root lockfile changed. This
target is optional in the public package: its ordinary workspace has no private
legacy rustls conflict, and remains the supported build entrypoint. Cache the
locked dependencies first if needed; `--offline` makes no network requests.

Eleven focused checks passed: two enrollment checks, seven driver/TLS/deadline
checks and two external public-API range checks. Actual loopback TLS verifies
that a valid CA/IP certificate with the wrong explicit leaf pin fails over to
the separately pinned source; an expired deadline creates no TCP connection.
Driver checks cover interrupted catch-up, differing source order and exact
duplicate resubmission, malformed complete-batch refusal, forged domain/status,
local-error STOP, source exhaustion and a nonrenewable cumulative deadline.
Synthetic receivers/carriers in these checks have no node verification authority.

The initial TLS fixture failed because its generated leaf was CA-marked; the
fixture was corrected, not the production verifier. A later fixture failed on
macOS-inherited nonblocking accepted sockets; explicitly returning the accepted
fixture socket to blocking mode corrected it. Both failures precede the final
passing source; neither is relabelled a pass or a real node consensus defect.

Scoped Clippy uses `-D warnings -A clippy::collapsible_if`: the allowance excludes
one pre-existing style lint in unchanged server/mining code, not an admission or
runtime check. It is not a claim of strict whole-workspace lint cleanliness.
Formatting/diff checks cover the changed files. No historical costly maturity,
proof-generation, canary, mining or relay experiment was repeated.

## Definite-rejection failover implementation — 1 October 2026

This increment addresses a concrete availability gap: one source's definite
invalid carrier previously prevented catch-up from any other configured source.
The ordinary node verifier and consensus bytes are unchanged. Four new focused
checks cover accepted-prefix retention, batch-suffix refusal, the unchanged
cumulative deadline across rejection failover, no repeat admission of rejected
bytes, actual node framing rejection with matching-source continuation, and
local STOP on uncertain errors, changed lineage or stale independent pins.
The cryptographic-error classification checks inject typed errors; they do not
generate proofs or claim an independently operated adversarial network journey.

Reproduce only the new checks with the same manifest/target command above,
replacing the filters with `--bin silk-f04-testnet rejection_ -- --test-threads=1`.
This is a local implementation increment, not deployment, full malicious-peer
recovery, history scaling, privacy acceptance or blockchain completion.

All four new checks and the two affected existing local-STOP/cumulative-deadline
checks passed. Scoped Clippy passed with the same pre-existing `collapsible_if`
allowance documented above; formatting and diff checks passed.

## Still unproven

The missing-parent increment adds two focused checks: source switching retains
the single deadline, does not ingest the refused batch's suffix, and does not
blacklist a child once another source supplies its parent; an actual fresh node
refuses the second unverified public carrier before any job and preserves READY
state, head, count, digest, accounting and its independent pin. The first check
uses a synthetic receiver; the second does not verify work or admit the child.
Neither is an independently operated withheld-body/partition journey.
Both new checks and the affected existing uncertain-error/stale-pin check passed.
Scoped Clippy retained the previously documented style allowance; no native
work, proofs or earlier completed catch-up/restart journey was repeated.

The original eleven checks are macOS components with genuine loopback TLS.
The small Linux receiver loss/restart check below adds actual local admission
and cold-process evidence, not a complete payment/proof journey or general
Linux resource qualification. Withheld data, divergent histories and broader
independently verifying node operation still need bounded runtime tests.
Independent machines/operators, authenticated open
discovery, Sybil/capture resistance, sustained operation, privacy, practical
speed, history beyond the existing horizon and production economics remain
separate gates. No bootstrap availability or deployment acceptance follows from
this source increment. Publication and any public-seed operation remain separate
decisions.

## Opt-in genuine receiver loss/restart check

The focused target now also contains the ignored
`sync::tests::live::genuine_pinned_catchup_peer_loss_and_process_restart`.
It is a real Linux node/ordinary-CLI check, not a synthetic Receiver. Run it
only in a separately qualified private-network, capped-store sandbox;
an environment flag alone does not qualify a host. No platform check, native
job deadline, work rule, consensus byte or aggregate runner limit is bypassed.

Inputs are exactly eight **UNVERIFIED**, already-mined public-zero carriers,
not a saved node directory or retained verification authority.
`prototype/checks/peer-sync-v1/extract_carriers.py` can extract their framing
from an explicitly SHA-256-pinned, read-only historical backup. Its output
identity establishes bytes only. A fresh source Node admits all eight through
ordinary work/parent/clock validation and reconciliation before exporting the
TLS fixture's snapshot. No new mining or payment-proof generation is needed.

The same small public input is checked in as
`prototype/checks/peer-sync-v1/public-zero-eight.hex`, so reproduction does not
require access to an operator's backup or a project-operated seed. Decode it
with `xxd -r -p` into a new owned input file. The 5,793 decoded bytes have SHA-256
`688bae6cdeef3a9896043518a0b0083ff778f3057b65a06e398af2389c23eb27`.
This is unverified full-carrier input, not a checkpoint, saved store, trusted
work cache or payment-proof fixture; the test grants credit only via Node admission.

The ordinary compiled `silk-f04-testnet` CLI initializes a fresh receiver and
executes three separate `sync --peers` processes:

1. The primary drops its actual TLS/socket connection after four accepted
   carriers. The backup is unavailable. Source exhaustion must exit78, retain
   those four carriers and leave a locally pinned Ready store that cold-opens.
2. A new process reopens that exact receiver using its independently retained
   pin, fails over from the unavailable primary to a separately pinned backup,
   restarts the backup's cursor at zero, locally checks duplicates and admits
   the remaining carriers to checkpoint1.
3. Another process cold-opens and repeats the full catch-up. Complete state,
   checkpoint, count and exported carrier bytes must still match the fresh
   source. Each cold-open must match its own externally retained local pin.

An additional fresh Node must refuse altered required-work bytes without graph
credit or head adoption. Normal CLI shutdown intentionally appends a local-clock
record; heads across process lifetimes/owners are not expected to be identical.
Source serving is synchronous so the two-thread test harness, one ordinary CLI
and its one native admission worker fit the unchanged TasksMax4. Every owned
CLI child is killed/reaped on failure; failed fixtures are retained, not retried.

After building the focused target's ordinary binary and test executable from
the same indexed source tree, invoke the executable directly in node mode:

```sh
env SILK_F04_ISOLATED_LAB=1 SILK_F04_PARAMETER_DIR=/work/parameters \
  SILK_F04_SYNC_BINARY=/work/TARGET/release/silk-f04-testnet \
  SILK_F04_SYNC_CARRIERS=/work/INPUT/carriers.bin \
  SILK_F04_SYNC_LAB=/work/store/NEW_OWNED_FIXTURE \
  /work/TARGET/release/deps/silk_f04_testnet-EXACT_HASH \
  --exact sync::tests::live::genuine_pinned_catchup_peer_loss_and_process_restart \
  --ignored --nocapture --test-threads=1
```

`TARGET`, `INPUT`, `NEW_OWNED_FIXTURE` and `EXACT_HASH` are placeholders, not
resolved runtime targets. Runtime source/toolchain/parameters must be read-only,
with only the owned capped store writable. This is deliberately a small
same-host transport/receiver test. TLS sources serve freshly verified snapshots,
not concurrently running production seed loops. It does not establish distinct
administration, permissionless discovery, divergent/withheld-history recovery,
arbitrary kill-boundary recovery, privacy, sustained operation or release readiness.

### Implementation-source evidence: 30 September 2026

The following experiment ran before projection onto this public package. Its
node admission source is byte-identical to the public base, and the added Rust
runtime/test code is carried across unchanged. This package receives focused
checks only: its genuine Linux journey has not been repeated, nor is private
source evidence promoted into independent public-package runtime acceptance.

The corrected, exact-source Linux test passed once: exit0, 11.66s test time,
11.711s service time, 10.856s CPU and 387.3MiB peak memory, no swap. Eight genuine
existing carriers were freshly admitted in both source and receiver stores.
The receiver retained four after actual socket loss/source exhaustion, then
two later ordinary CLI sync processes cold-opened, converged and matched full
state/checkpoint/count/carrier bytes. A locally altered work claim received no
graph credit or head adoption. All four owned CLI PIDs were reaped/absent and
both fixture listener ports were closed at closeout. The runtime intent closed.

The unchanged runner's node-mode settings were separately read while active:
4GiB MemoryMax, zero swap, TasksMax4, one-CPU quota, 30-minute aggregate ceiling,
private networking/devices/IPC, no capabilities and no-new-privileges; `/work`
read-only with only the capped owned store writable. The full test used this
same runner/mode. Post-collection systemd snapshots contain reset defaults,
not live limits; those are not used as qualification evidence. A later kernel
cap read after probe collection was unavailable, not a kernel-limit PASS.
This is reuse of the already qualified isolated runner plus live configuration
checks, not new universal Linux resource assurance.

The initial runtime attempt FAILED during certificate setup before any Node
admission: the sandbox omits the host OpenSSL config. The fixture was corrected
to use explicit `/dev/null` configuration and unchanged explicit certificate
extensions; no host paths were exposed or verifier weakened. That failed fixture,
binary and receipt remain retained. The original extracted-archive build also
failed its required Git check; exact indexed source/RandomX bytes were restored,
not bypassed. Neither failure is relabelled a pass or a blockchain defect.

All eleven existing component checks pass on the corrected source; the one
genuine runtime test is additional, not twelve independent privacy/security
acceptances. Scoped lint and formatting pass under the inherited style allowance
above. No new mining, payment-proof construction, long maturity/canary/benchmark,
public seed recovery/start, remote service deployment or publication occurred.
The checked-in public input and ordinary CLI reproduction remain subject to
narrow disclosure review, not automatic publication or whole-core completion.
