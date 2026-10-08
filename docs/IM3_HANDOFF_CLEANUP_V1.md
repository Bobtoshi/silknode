# IM3 wallet handoff and recoverable preparation cleanup

Two bounded source corrections, still nonproduction research. IM3 remains
default-off. No protocol activation, public service, new trusted setup or
consensus/payment/proof/wire format change is introduced.

## One normal-wallet handoff

`silk-f04-wallet::journal::intents` deliberately narrows its public API:

- `offer_ready(pin)` checks a pinned `MayHaveEscaped` payment without exporting
  bytes or consuming a handoff.
- `offer_saved(pin, &mut retention)` first durably records `HandoffConsumed`
  with the unchanged plan/signed envelope, then invokes `IntentPinRetention`
  for both new wallet heads, and only then returns one non-cloneable offer.
- Raw `release_saved_envelope` is now crate-private and test-only. It is not
  an application bypass or supported production recovery/export API.

Callers must migrate from the old one-argument offer API and independently
retain the new address/payment heads. An uncertain or failed retention returns
no offer but leaves handoff consumption in place. No timeout, profile/round
change, cancellation or reopen authorizes a second issuance of that payment.

Authenticated history retains every exposed real-input nullifier and note
commitment as a local exclusion. A changed note position/nullifier cannot evade
commitment exclusion; a distinct later payment does not clear earlier history.
Reopen authenticates the complete pinned predecessor chain. Local accepted-effect
and nullifier observation can use the retained internal signed envelope without
retransmission; missing latest independent pins can instead fail closed.

This prevents repeated journal issuance under those assumptions, not arbitrary
recipient retransmission: trusted code can copy bytes after consuming the offer.
The retention trait cannot prove callback honesty or protect coordinated rollback
of both journal and pins. Key-only, cross-device or malicious-backup rollback
resistance and successful delivery are not established.

## Cleanup-only original connection

The original IM3 client's enclosing `run` driver handles recoverable preparation,
worker and verification errors by destroying its owner/frame/submission authority
and finishing cleanup before returning the error. Worker file/encoding/binding
and timeout failures in the retained fixture now return errors into this path.

`Transport::into_cleanup` irreversibly drops TLS state, zeroes pending record
buffers and moves the same nonblocking TCP socket and resource permits into
`CleanupOnly`. That type exposes closure polling/finishing, no application write,
proof, reconnect, transport recovery or deadline-renewal API. The driver uses
the existing thread, without spawning a task or worker, to retain the original
socket until T+44 or detectable peer closure. A hard sixty-second cap also
bounds misuse; the admitted T-8..T+44 interval fits within it. Unexpected inbound
bytes or nonterminal I/O errors do not renew authority or shorten retention;
EOF behind unread bytes may only be detected at the fixed boundary.

This applies while the enclosing owner/process survives. Drop alone closes the
socket; panic, arbitrary abandonment and process/host death are not masked.
Admission and manifest-polling refusals retain their separate immediate-quarantine
behavior. No uniform timing claim covers those earlier failures or host scheduling.
Original proof deadlines and selected transmit slots remain unchanged.

## Fixed-size source work, unchanged validation

Real and cover choices each allocate/copy a full 2,790-byte payload, evaluate
envelope framing and manifest bindings, and scan the complete payload for zero
cover. Both copy the full payload into the prepared 4,096-byte cell. Complete
payload/padding reductions replace early-ending scans. The Sapling framing parser
evaluates its existing version/reserved, domain, counts/fee and distinct-nullifier
conditions before returning errors in the original precedence.

Invalid real bytes still reject; they cannot silently select cover. Valid real
and cover bytes, message derivation and complete-32 proof/gate requirements are
unchanged. These are source-level scans/copies, not compiled constant-time
evidence, equal proving time or equal joint miss/deadline distributions.

## Source and evidence scope

Accepted private source pins are
`934dbed690c143106c80f62e32553d64f7b7ce54` (wallet handoff) and its successor
`1d8b8931131b10c9976895ebb709564bd52bc788` (cleanup/fixed source work).
The public delta copies the ten necessary runtime source files exactly from
these accepted committed objects and minimally adapts the existing curated
client tests: the offer caller, checked worker errors, fixed-payload assertions
and cleanup selectors. Private WIP and unrelated fault/readiness scaffolding,
fixtures, credentials, job/proving secrets, keys, evaluator truth/reveal maps,
internal receipts and private Git ancestry are excluded.

The writer reports focused VPS checks. Independent reviews accepted the exact
bounded source corrections and their document/source bindings; they did not
independently fetch/replay runtime receipts or reproduce execution. No build,
test, native run, proof or benchmark was performed for this public candidate.
Original tests and the curated public harness are not interchangeable execution
subjects. No new consumed-state end-to-end settlement, exhaustive crash/fault
matrix, genuine prover-failure comparison or both-lane privacy run is established.

Full joint timing/deadline privacy, system-wide anonymity, independent custody,
malicious rollback/retransmission guarantees, crash masking and release readiness
remain unsupported. Historical demonstrations in [status](../STATUS.md) remain
separate; none is retroactively evidence for this correction.
