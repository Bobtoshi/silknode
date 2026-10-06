# Third-party notices

Third-party components remain under their upstream terms. The root SilkNode
licence does not relicense them. This candidate contains source, not compiled
binaries or downloaded Sapling parameter bodies.

## Vendored RandomX

`prototype/vendor/RandomX/` contains a curated v2.0.1 source tree, preserving
upstream copyright/licence notices and native source. See
its `LICENSE` (BSD-3-Clause), source headers and
[source provenance](prototype/docs/RANDOMX_V2_PROVENANCE.md). Embedded Argon2 and
Blake2 material carries its own CC0 notices. Keep the curated vendor tree intact;
its exact Git tree identity is part of the build check.

Four upstream audit PDFs are linked, not redistributed, because their
redistribution grants have not been established for this package:

- [Kudelski Security report](https://github.com/tevador/RandomX/blob/aaafe71322df6602c21a5c72937ac284724ae561/audits/Report-Kudelski.pdf)
- [Quarkslab report](https://github.com/tevador/RandomX/blob/aaafe71322df6602c21a5c72937ac284724ae561/audits/Report-Quarkslab.pdf)
- [Trail of Bits report](https://github.com/tevador/RandomX/blob/aaafe71322df6602c21a5c72937ac284724ae561/audits/Report-TrailOfBits.pdf)
- [X41 D-SEC report](https://github.com/tevador/RandomX/blob/aaafe71322df6602c21a5c72937ac284724ae561/audits/Report-X41.pdf)

These reports concern upstream RandomX, not an audit of SilkNode. The vendored
README's audit link is redirected upstream; no native algorithm source changes
are part of this curation.

## Rust registry dependencies

[LICENSES/dependencies.tsv](LICENSES/dependencies.tsv) lists declared SPDX
licence metadata and archive checksums for the packages in the candidate
lockfile, including optional, build, development and platform-specific packages.
It is not a claim that all entries are linked into every binary. Legacy
`MIT/Apache-2.0` declarations are normalized to `MIT OR Apache-2.0`.

Cargo obtains these packages separately using `prototype/Cargo.lock`; their
sources are not vendored here. Keep upstream licence/copyright files when
redistributing their source or binaries. In particular, `ring` declares
`Apache-2.0 AND ISC`, and `unicode-ident` also requires Unicode-3.0 terms.
An inventory is not a substitute for the actual upstream licence/notice texts
or a legal opinion. A future binary or vendored-dependency release needs its
own applicable notice bundle.

The separately authenticated `atomic-polyfill` 1.0.3 and `critical-section`
1.2.0 packages both declare `MIT OR Apache-2.0` and include both full licence
texts. Their MIT notices name Dario Nieuwenhuis (2020) and the critical-section
authors (2022), respectively.

## Sapling ceremony files

The optional acquisition tool references canonical files hosted by the Zcash
project and verifies the complete pinned bytes before use. Parameter bodies
and any rights to redistribute those bodies are not granted by this repository.
Their acquisition and ceremony trust assumptions are separate from the source
licences above.

## Optional R2 preparation parameters

The default-off R2 preparation module uses separately obtained arkworks 0.5.0
registry packages; their declared terms and archive checksums are included in
the dependency inventory above. No proving-key or trusted-setup artifact is
distributed with this module.

The numeric Poseidon table in `aip2_poseidon_constants.rs` was mechanically
decoded from `poseidon-lite` 0.3.0 `constants/2.js`, not from its executable
JavaScript implementation. Upstream declares versions 0.2.0 and later MIT;
see the [upstream version-specific licensing statement](https://github.com/chancinald/poseidon-lite#license).
The source provenance and exact input hash are recorded in
[the preparation notes](docs/AIP2_R2_PREPARATION_V1.md). This is provenance and
licensing metadata, not cryptographic setup acceptance or an upstream audit of
SilkNode. Preserve applicable upstream terms when redistributing material.
