# Security

This is experimental, nonproduction software. Do not use real funds, production
seeds or identifying transaction data. There is no supported production release,
security warranty, audit claim or bug-bounty commitment.

Cryptographic primitives do not by themselves establish network anonymity.
Relay collusion, traffic analysis, endpoint compromise, implementation defects,
clock assumptions and resource exhaustion remain material considerations.
Do not expose the local demonstration or disable validation/resource refusals.

The optional IM3 path is default-off research, not an anonymity guarantee.
Its three-relay design still depends on an honest middle relay and unproven
composition, timing, setup and custody assumptions. A separate earlier R2
two-relay fixture demonstrated colluding-relay linkability; IM3 must not be
treated as making that older path safe. One reviewed hidden-assignment IM3
trial rejected one predeclared timing/order hypothesis only. It does not rule
out weaker statistical advantage, other attacks, compromised endpoints or
failure-path leakage. The latest private fault attempts stopped before the
intended honest fault path and are not successful privacy evaluations.

Public fixture signing seeds and test certificates are deliberately known.
They are not separate custodians or production credentials. No accepted IM3
setup/provenance, operational clock profile or independently operated anonymity
cohort is distributed here. Do not create real identities or send identifying
traffic through the lab examples. See [status](STATUS.md) and
[IM3 limits](docs/IM3_EXPERIMENTAL_V1.md).

Never post spending keys, viewing keys, backups, private logs, credentials or
identifying traffic captures in a public issue. Public test seeds and generated
test certificates in this source must never be reused as real identities.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Bobtoshi/silknode/security/advisories/new)
for this repository. Sign in to GitHub, then submit the private report through
that form, not a public issue or pull request. Include the affected revision,
impact and a minimal redacted reproduction; never include real wallet secrets.
GitHub private vulnerability reporting is enabled for `Bobtoshi/silknode`.

If the private-report form is unavailable, do not post sensitive details
publicly. A non-sensitive issue may ask the maintainer to restore the private
channel. Non-sensitive build issues can include the revision, platform and a
minimal redacted reproduction. No response-time guarantee is made.
