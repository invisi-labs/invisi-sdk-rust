# Rust SDK 1.2.9 local release validation

All eight public crates use version `1.2.9`. Workspace sibling dependencies carry both
the development path and exact registry version `=1.2.9`. The examples package remains private at `0.1.0` and consumes SDK
`1.2.9`. This release does not change the C ABI version.

Run from the repository root with Rust/Cargo and Python 3.12 or newer:

```sh
python3 scripts/check-boundaries.py
cargo test --locked --workspace --all-features
python3 scripts/check-release.py --work-dir /tmp/invisi-rust-release-1.2.9
```

The release check vendors locked third-party dependencies into its temporary working
directory. It builds a local directory source for the unpublished sibling versions,
then runs `cargo package --locked --offline` with Cargo's verification enabled for
primitives, protocol, prover, RPC, SDK, Session, FFI, and IPP in that order.
Each actual archive replaces its bootstrap directory entry before downstream checks.
The script separately unpacks each archive and compiles all targets with all features,
resolving siblings as registry packages from the local source rather than workspace
paths. It rejects generated/private artifact paths. It does not invoke publishing,
create tags, push branches, or modify a remote registry. An existing `cargo vendor
--locked` directory may be reused with `--vendor-dir /tmp/path`. Reusing a work directory
removes its `target/` build artifacts before validation: Cargo treats registry
versions as immutable, so compiled unpublished sibling versions must not be cached
between checks. Only the vendored dependency sources are reused.

Each archive includes the existing Apache-2.0 license, attribution, source, and the
explicitly allowlisted runtime assets and fixtures. Protocol ABIs, gas references,
provenance manifests, and compile-time test fixtures remain available outside the
workspace. Heavy main and Provenance circuit artifacts/VKs are external Core resources;
archive checks reject bundled Provenance circuit trees. The prover's generated
`assets/prover/resource-release.json` pins the resource index. Seed an offline cache
with `python3 scripts/sync-prover-assets.py /path/to/core-release --cache /path/to/cache`;
`--update-pin` deliberately accepts a reviewed new release. To validate the pinned Core
release against existing Rust circuit/Source identities and offline cache replay, run
`INVISI_TEST_RESOURCE_SOURCE=/path/to/core-release cargo test -p invisi-sdk-prover resource_tests --lib -- --include-ignored`.
Public recursive verification data and the test verification key are
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


## Publish from GitHub Actions

The eight packages retain the `invisi-sdk` names and version `1.2.9`.
Publishing runs in [Release Rust SDK](https://github.com/invisi-labs/invisi-sdk-rust/actions/workflows/release.yml)
on a pushed `vMAJOR.MINOR.PATCH` tag, or a manual dispatch naming an existing tag.
If GitHub has not registered a newly added release workflow yet, manually dispatch
the [Release Rust SDK workflow](https://github.com/invisi-labs/invisi-sdk-rust/actions/workflows/release.yml)
from the release feature branch with the same `tag` input. It invokes the reusable
release job, which checks out the immutable tag rather than publishing branch source.
The checked-out commit must match that tag; all eight public package versions and
exact sibling requirements must match it. Fork repositories and dirty checkouts
are rejected. Rust/Cargo is pinned to 1.94.0 so retries produce the same archive format.

The repository's existing `CARGO_REGISTRY_TOKEN` Actions secret publishes the eight
registered crates. Never put the token in source, workflow inputs, logs, or chat.
No local `cargo login` or local `cargo publish` is required. The workflow checks
for the secret before expensive validation.

Push the approved release commit and its `v1.2.9` tag only after review. A workflow
dispatch can retry the same existing tag after an interrupted run; it must not
move the tag or change its source to bypass a registry conflict. Rust intentionally
skipped 1.2.1; the 1.2.2 changelog records capabilities added since 1.2.0.

Before the first registry write, the workflow runs release-helper regression
tests, English and module-boundary checks, formatting, clippy, debug workspace tests, native export validation, an example, and isolated package/archive
compilation checks. External native Noir/BB cases still require their explicit assets and are
not silently represented as CI coverage.

The publishing helper packages each crate from the clean **tagged checkout** with
normal Cargo verification, authenticates its `.cargo_vcs_info.json` commit and
package identity, and publishes in dependency order: primitives, protocol, prover,
RPC, SDK, Session, FFI, IPP. It checks crates.io metadata, the sparse index, and the
downloaded archive against the exact tagged local archive's SHA-256 before moving
to the next crate. HTTP 429/transient failures and indexing delays use bounded
retries. It never overwrites or yanks a version, and skips an existing version only
when it is not yanked and its checksum matches exactly. A conflict fails the job.
Archives from earlier local `/tmp` validation runs are never used as release identity.

Only after all eight registrations verify does the workflow create the GitHub
release, attaching the exact archives and `invisi-release-checksums.json`. The
report is also retained as a workflow artifact. An already-existing GitHub release
is preserved on retry. A partial registry release can be resumed from the same tag;
immutable published versions cannot be rolled back by editing the workflow.

Release notes use the local versioned CHANGELOG as the only maintained source.
`scripts/release-notes.py vMAJOR.MINOR.PATCH --output NOTES.md` renders the complete
current entry (all public package entries for TypeScript) into the GitHub Release
body. Missing, duplicate, empty or link-only entries fail validation before
publication. Historical entries are retained locally; a release body includes only
its matching version. Release retries update the same body from the same source.

### CI reuse

Push CI runs only on `develop` and `main`; pull-request CI remains enabled. These checks use the shared `verify.yml` workflow. Tag pushes only trigger release. A release reuses successful `develop` or `main` push CI for the exact tagged commit; when none exists, it runs shared verification before publishing. In-progress CI is not accepted as success. Compilation dependencies are cached; isolated archive sources remain fresh. Release-mode native exports are still checked, while workspace tests run once in debug mode. Package verification compiles all archive targets instead of repeating the workspace test suite. Registry publication continues to validate clean tag identity, exact sibling versions, immutable archive checksums, and registry propagation.
