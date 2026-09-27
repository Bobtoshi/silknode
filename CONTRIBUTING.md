# Contributing

Start with the [README quick start](README.md) and [module map](ARCHITECTURE.md).
Prefer one small, explainable change with focused checks and an explicit account
of what was not tested. Do not treat a passing fixture as a privacy or security
proof. Do not run expensive proof, mining or long-history suites by default.

Preserve versioned interfaces, consensus/commitment bytes, fail-closed behavior
and upstream notices. Protocol changes need a clear versioning and compatibility
proposal. Avoid live credentials, host-specific paths, runtime dumps, parameter
binaries or generated build artifacts in commits.

Compact tests are included; external-parameter and bounded-runtime fixtures are
not a one-command public network. Two old Gate-2 corpus integration modules and
their large generated data are omitted together. Scope any additional test run
to the code being changed, with appropriate local resource limits.

Use Rust 1.93.0 and format changed Rust files. Keep dependency versions/checksums
pinned; include the reason and refresh licence metadata for dependency changes.
Contributions follow [LICENSING.md](LICENSING.md); retain attribution and identify
third-party material. Publication and release decisions are separate from a
local build. See [SECURITY.md](SECURITY.md) before reporting sensitive findings.
