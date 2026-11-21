# invisi-sdk-prover

Version `1.2.9`. Local witness construction, authenticated proving artifacts, prove/verify and recursive aggregation. Depends on primitives and public protocol contracts.

See the [workspace documentation](https://github.com/invisi-labs/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

## Contributing

See the [contribution guidelines](../../README.md#contributing) for issues, pull requests, validation, and handling sensitive material.

Public circuit resources are loaded lazily by `ResourceProvider` and `NativeProver::new`.
The generated `assets/prover/resource-release.json` pins the independent Core release
index, Noir 1.0.0, and BB 6.0.0. Resources are size/hash checked on each cache read;
misses download only public artifacts, with bounded timeout and atomic publication.
Witnesses never enter the resource transport. `ResourceOptions` supports an explicit
HTTPS/object-directory source, cache directory, published object directory (or a logical asset layout), and offline mode.
Existing `NativeProver` struct literals and `DirectoryAssets` remain supported.

The default disk cache is the system cache directory plus `invisi/prover-assets`:
`~/Library/Caches/invisi/prover-assets` on macOS,
`${XDG_CACHE_HOME:-~/.cache}/invisi/prover-assets` on Linux, and
`%LOCALAPPDATA%/invisi/prover-assets` on Windows.
An explicit cache option overrides `INVISI_PROVER_CACHE_DIR`, which overrides this default.
Index files use `<index-sha256>.index.json`; objects use `<sha256>.json` or `<sha256>.vk`,
so Node, Go and Rust can share the same verified disk cache. Offline mode defaults to false.

Local directories support `<pin>.index.json` before `index.json`. For per-set mirrors,
`ResourceOptions.source` accepts an explicit `{pin}` placeholder; it is resolved for
each trusted circuit set. A flat mirror can host pin-named indices and hashed objects.

## Capability-specific catalogs

`ResourceProvider` selects the independent Core catalog for all Core circuits (including initial-payment) and the Provenance catalog for `provenance/` resources. `ResourceOptions` provides `provenance_source`, `provenance_directory` and `provenance_index_sha256` separately from Core. Cache and offline settings are shared. A static Core source is not reused for Provenance; a `{pin}` template explicitly allows a shared mirror.

Provision with `python3 scripts/sync-prover-assets.py CORE_OUTPUT --set core --cache CACHE` and the same command with `PROVENANCE_OUTPUT --set provenance`. The two verified catalogs can share one cache. `legacy_combined: true` selects historical combined snapshots; provision those with `--set legacy` and `--set legacy-initial-payment`. No missing/corrupt catalog automatically downgrades to legacy. New split catalogs require independent publication before SDK release.

## Recursive verification keys

Aggregation loads binary keys through the selected `Prover::load_verification_key`
capability. `NativeProver` delegates to its configured `Assets`; `ResourceProvider`
loads just the requested VK from the authenticated catalog and `DirectoryAssets`
loads the pinned local VK. The capability accepts published Core circuit names and
targets; `invisi_sdk_protocol::statements::verification_key_sha256` exposes their
pinned binary identity without loading resources. Custom `Prover` and `Assets`
implementations remain source compatible: their default loader returns an explicit
unsupported error. Implement the optional method to enable aggregation.

Constructing a prover performs no I/O. Dedicated aggregation loads one C1–C10
recursive key; mixed aggregation loads C1–C5. Each key must match its pinned SHA-256,
contain exactly 115 canonical 32-byte BN254 field words, and reproduce the trusted
Poseidon commitment over domain `0x494e564953495f5245435552534956455f564b31`, the
115 fields, and the key hash. Only small key hashes and commitments are bundled.
Member and resulting outer proofs are still verified independently. The configured
source, cache, directory, offline and explicit legacy policies also govern these loads.

For producer synchronization, run `python3 scripts/sync-recursive-keys.py CORE_EXPORT_ROOT`
with an exported `circuits/transact/manifest.json` (or `--manifest RELATIVE_PATH`).
The script authenticates the binary against the reviewed circuit catalog and the
VK JSON against its export digest, checks canonical JSON fields equal the binary,
and validates key hash/commitment trust anchors before writing metadata only.
It does not update release pins. Run its regression tests with
`python3 scripts/test-sync-recursive-keys.py`.
