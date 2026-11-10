# Rust SDK 1.2.0 local release validation

All seven public crates use version `1.2.0`. Workspace sibling dependencies carry both
the development path and exact registry version `=1.2.0`. The examples package remains private at `0.1.0` and consumes SDK
`1.2.0`. This release does not change the C ABI version.

Run from the repository root with Rust/Cargo and Python 3.12 or newer:

```sh
python3 scripts/check-boundaries.py
cargo test --locked --workspace --all-features
python3 scripts/check-release.py --work-dir /tmp/invisi-rust-release-1.2.0
```

The release check vendors locked third-party dependencies into its temporary working
directory. It builds a local directory source for the unpublished sibling versions,
then runs `cargo package --locked --offline` with Cargo's verification enabled for
primitives, protocol, prover, RPC, SDK, Session, and FFI in that order.
Each actual archive replaces its bootstrap directory entry before downstream checks.
The script separately unpacks each archive and runs its tests with all features,
resolving siblings as registry packages from the local source rather than workspace
paths. It rejects generated/private artifact paths. It does not invoke publishing,
create tags, push branches, or modify a remote registry. An existing `cargo vendor
--locked` directory may be reused with `--vendor-dir /tmp/path`. Reusing a work directory
removes its `target/` build artifacts before validation: Cargo treats registry
versions as immutable, so compiled unpublished sibling versions must not be cached
between checks. Only the vendored dependency sources are reused.

Each archive includes a README, the existing Apache-2.0 license, source, and the
explicitly allowlisted runtime assets and fixtures. Protocol ABIs, gas references,
provenance manifests, and compile-time test fixtures remain available outside the
workspace. Public recursive verification data and the test verification key are
required by the prover source and are included; private proving keys, local proof
outputs, caches, wallet databases, target directories, and vendored dependencies are
excluded. Fixture copies used across package boundaries must be refreshed alongside
their original source fixture.

This local check establishes package contents, registry version resolution, builds,
and ordinary tests. It does not establish registry name ownership/credentials,
external circuit asset availability, native Noir/BB integration, live chain/RPC
behavior, or platform-specific dynamic-library compatibility. The real source proof
test remains explicitly ignored unless its pinned external assets and executables
are configured. Publishing, if separately authorized, must follow the same dependency
order and wait for each preceding registry version to become available.
