# RandomX v2 curated source pin

This experimental distribution builds a curated copy of RandomX `v2.0.1`.
The wrapper accepts only the v2 algorithm flag and does not expose JIT,
full-memory dataset, large-page or hardware-AES choices.

- Upstream: <https://github.com/tevador/RandomX>
- Upstream release: `v2.0.1`
- Upstream commit: `aaafe71322df6602c21a5c72937ac284724ae561`
- Original upstream tree: `57752798bc713766b34b487737b8d9258448814e`
- Curated vendor tree enforced by the build: `bee7375373c0b822a04527e954d948dc5cbb3f23`
- Curated file count: `167`

The curated copy omits four audit PDFs whose redistribution grants have not
been established: `Report-Kudelski.pdf`, `Report-Quarkslab.pdf`,
`Report-TrailOfBits.pdf` and `Report-X41.pdf`. It redirects the vendored README's
audit-directory link to the pinned upstream copy. These are the only changes
to the upstream vendor tree: all native source, headers and build definitions
remain byte-identical. [Third-party notices](../../THIRD_PARTY_NOTICES.md)
attribute and link each report. Those upstream reports are not SilkNode audits.

## Reproduce the vendor identity

From the repository root of a clean Git checkout:

```sh
git rev-parse HEAD:prototype/vendor/RandomX
git ls-tree -r --name-only HEAD:prototype/vendor/RandomX | wc -l
```

The first command must return the curated tree above; the second returns `167`.
The build enforces the index's tree, which can be checked separately:

```sh
git rev-parse "$(git write-tree):prototype/vendor/RandomX"
```

The Git tree identity covers file paths, modes and blob identities. No separate
unreproducibly specified archive hash or snapshot identifier is used here.
`RANDOMX_UPSTREAM_TREE` records upstream provenance; `RANDOMX_CURATED_TREE`
records the tree actually exported and compiled. Neither is a new consensus
algorithm identifier.

The build exports the verified indexed tree into Cargo's output directory before
invoking CMake, so generated assembly/build output does not change vendor files.
Independent upstream authorship/origin authentication is not claimed. This pin
does not prove ASIC resistance, decentralization, mobile viability, public
network security or production readiness.
