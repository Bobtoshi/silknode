# Optional exact-cohort R2 preparation

This candidate adds inspectable Rust preparation components, not an operational
anonymous network. No production profile, accepted setup, qualified clock or
delivery bound is bundled. Defaults, payment/consensus bytes and the public
testnet release policy are unchanged. No new daemon or public endpoint is added.

The Unix-only `aip2_claim` module provides durable one-shot `(profile, round)`
consumption with independently selected pin retention and consumed-on-uncertainty
semantics. The optional, default-off `aip2-preparation` feature adds:

- Strict co-signed 1312-byte profile validation, fixed 32-member depth-five tree,
  canonical commitments and locally expected context/full verification-key pin.
- Explicit message/scope conversion, strict BN254 point/field admission and
  actual Groth16 pairing verification using arkworks 0.5.0.
- Version-separated double-HPKE cells and a complete 32-proof/distinct-nullifier
  gate before real Sapling work. Counts and caller validity booleans are not
  cryptographic authority; legacy batches cannot substitute for this capability.

The R2 runtime constructors additionally require `functional-lab`, an explicitly
unqualified schedule and the original whole-round native guard. They are named
`new_r2_lab`; there is no operational-profile admission or production conversion.
The ordinary relay path remains separate. The original two-CPU-second round
lease is not reset when proof processing begins.

## Inspect and test

Use the repository's pinned Rust toolchain and normal build prerequisites.
Use a Unix test filesystem satisfying the original journal host-margin check;
do not point test `TMPDIR` at a small capped build-cache filesystem. This is an
existing fail-closed storage requirement, not a reason to relax its threshold.
These focused checks require no proving-key download, wallet secret, mining,
listener, new membership proof or trusted-setup ceremony:

```sh
cd prototype
CARGO_BUILD_JOBS=1 cargo test --locked --release -p silk-f04-relay --lib
CARGO_BUILD_JOBS=1 cargo test --locked --release -p silk-f04-relay --lib \
  --features aip2-preparation
CARGO_BUILD_JOBS=1 cargo test --locked --release -p silk-f04-relay --lib \
  --features aip2-preparation,functional-lab
```

The exact candidate's offline Linux library checks passed 36 default, 54
preparation and 56 double-gated lab tests. These include durable-claim,
signed-profile and strict field/point/subgroup admission checks; they are not
a fresh proof-generation, live-client or operational-network qualification.

Also inspect `aip2_claim.rs`, `aip2_profile.rs`, `aip2_proof.rs`,
`aip2_transport.rs`, and the double-gated source/exit owner changes. Profile and
codec tests use explicitly public fixture integers/signing seeds. Their success
does not establish independent participants or accepted cryptographic setup.
No witness/proving-key files, credential secrets or internal execution controller
are included in this source addition. It is not a turnkey reproduction of the
separate native journey; a verifier pin authenticates bytes, not setup soundness.

## What the separate native journey did and did not establish

A private, valueless, one-host/operator functional fixture used a newly generated
two-input Sapling payment and genuine 32-member proofs. Each actual producer
release passed through `ProducerInboxV1` to a local offer, ordinary node ingress
admitted eight genuine work records, and a distinct cold process recovered the
node and both encrypted wallets. Duplicate work received no extra credit.
Recipient value8 and sender change1 remained pending maturity; no recipient
respending claim follows. The producer-to-offer adapter itself was already in
the preceding public source; this addition exposes the R2 preparation gate.

The first real-clock attempt failed a fixed transmit slot. The accepted software
composition used exact reusable statements/ciphertexts and explicitly shifted
protocol UTC in new fixture owners. It did not reopen failed owners, retarget a
proof, widen a protocol slot or establish live reliability. Native monotonic/CPU
guards remained genuine. Independent review accepted that software-fixture
scope only, not operational timing, setup, custody, anonymity or release readiness.
Subsequent timing regressions are separate evidence and cannot retroactively
turn that failure into a pass.

One subsequent actual-UTC functional regression independently passed review:
32 new genuine membership proofs, unchanged relay/client binaries, the original
public payment/genesis, actual A-to-B per-frame transmission, three completed
producer handoffs and cold authority fences. It precomputed stage2 inputs; it
did not test 32 real-client source links, fixed five-second dispatch, new node
settlement or new wallet recovery. This is one functional pass, not sustained
network qualification. Failed runs and corrected cleanup-inclusive accounting
were retained separately.

Still required: accepted exact-relation setup/provenance, independent custody,
fixed five-second client dispatch, external clock/delivery qualification, all
per-frame deadlines, 32-real worst-case resource margin, adversarial composition
and genuinely independent plausible senders. Two colluding relays can join their
maps; a lone honest sender can be identified by subtraction. This code does not
solve those limits or establish Monero-equivalent privacy.

Poseidon numeric parameters are mechanically decoded from poseidon-lite 0.3.0
(`constants/2.js` SHA-256
`d16a6c48eb9042073ec7b04433bc79ab17a648d59a106a18d7ee4f85b29431c5`).
The table is width3, eight full/57 partial rounds over BN254 Fr: Poseidon with two
inputs, not the distinct Poseidon2 permutation. Upstream executable JavaScript
is not vendored. Dependency licences and the research trust boundary remain
applicable; historical upstream audits do not accept this composition.
